require('dotenv').config();
const {
  Client,
  PrivateKey,
  AccountId,
  AccountCreateTransaction,
  TokenAssociateTransaction,
  TransferTransaction,
  ContractId,
  AccountBalanceQuery,
  Hbar,
  TokenId,
  ContractExecuteTransaction,
  ContractFunctionParameters,
} = require('@hashgraph/sdk');
const twilio = require('twilio');
const express = require('express');
const axios = require('axios');
const logger = require('./logger');
const multer = require('multer');
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Redis = require('ioredis');
const NodeCache = require('node-cache');
const { promisify } = require('util');

// Config Validation
const requiredEnv = [
  'HEDERA_ACCOUNT_ID', 'HEDERA_PRIVATE_KEY', 'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN',
  'TWILIO_WHATSAPP_NUMBER', 'MPESA_CONSUMER_KEY', 'MPESA_CONSUMER_SECRET', 'MPESA_SHORTCODE',
  'MPESA_PASSKEY', 'CALLBACK_URL', 'NODE_ENV', 'PREMIUM_TOKEN_ID', 'CLAIMS_CONTRACT_ID',
  'MONGODB_URI', 'JWT_SECRET', 'REDIS_URL'
];

for (const env of requiredEnv) {
  if (!process.env[env]) throw new Error(`Missing required env var: ${env}`);
}

// Initialize core services
const accountId = process.env.HEDERA_ACCOUNT_ID;
const privateKey = PrivateKey.fromString(process.env.HEDERA_PRIVATE_KEY);
const client = (process.env.NODE_ENV === 'development' ? Client.forTestnet() : Client.forTestnet())
  .setOperator(accountId, privateKey)
  .setMaxAttempts(3)
  .setRequestTimeout(10000);


console.log(process.env.NODE_ENV);

logger.info(`Client initialized with operator: ${accountId}`);
if (!accountId || !accountId.startsWith('0.0.')) {
  throw new Error(`Invalid HEDERA_ACCOUNT_ID: ${accountId}`);
}
if (!privateKey) {
  throw new Error('HEDERA_PRIVATE_KEY is invalid or missing');
}

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const app = express();
const port = process.env.PORT || 3000;
const premiumTokenId = TokenId.fromString(process.env.PREMIUM_TOKEN_ID);
const claimsContractId = process.env.CLAIMS_CONTRACT_ID;
const mongoUri = `${process.env.MONGODB_URI}`;
const mongoClient = new MongoClient(mongoUri, { maxPoolSize: 20 });
let db;

// Redis setup
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
redis.on('error', (err) => logger.error(`Redis error: ${err.message}`));
const redisGetAsync = promisify(redis.get).bind(redis);
const redisSetAsync = promisify(redis.set).bind(redis);

// Fallback in-memory cache
const localCache = new NodeCache({ stdTTL: 3600 });

// M-Pesa Config
const mpesaConsumerKey = process.env.MPESA_CONSUMER_KEY;
const mpesaConsumerSecret = process.env.MPESA_CONSUMER_SECRET;
const mpesaShortcode = process.env.MPESA_SHORTCODE;
const mpesaPasskey = process.env.MPESA_PASSKEY;
const callbackUrl = process.env.CALLBACK_URL;
const mpesaBaseUrl = process.env.NODE_ENV === 'production'
  ? 'https://api.safaricom.co.ke'
  : 'https://sandbox.safaricom.co.ke';

// Helper Functions
const generateClaimId = () => {
  const rand = crypto.randomBytes(16).toString("hex");
  return `claim_id_${rand}`;
};

// Connect to MongoDB
async function connectToMongo() {
  try {
    await mongoClient.connect();
    db = mongoClient.db('hashguard');
    await db.command({ ping: 1 });
    logger.info('Connected to MongoDB Atlas');
    return db;
  } catch (error) {
    logger.error(`MongoDB connection failed: ${error.message}`);
    throw error;
  }
}

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 'https://your-frontend-domain.com' : '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
}));
app.use((req, res, next) => {
  if (!db) {
    logger.warn('Database not connected yet');
    return res.status(503).json({ error: 'Service unavailable, please try again later' });
  }
  next();
});

// Enhanced Authentication Middleware with Token Expiration Handling
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      error: 'Authentication required',
      redirect: '/login',
      reason: 'No token provided'
    });
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    const currentTime = Math.floor(Date.now() / 1000);
    
    // Check if token has expired (1 hour = 3600 seconds)
    if (user.exp < currentTime) {
      logger.info(`Token expired for user ${user.phone}`);
      return res.status(401).json({ 
        error: 'Session expired',
        redirect: '/login',
        reason: 'Token has expired after 1 hour of inactivity'
      });
    }

    req.user = user;
    const rider = await db.collection('riders').findOne({ phone: user.phone });
    if (!rider) {
      return res.status(401).json({ 
        error: 'User not found',
        redirect: '/login',
        reason: 'Account not found in database'
      });
    }
    
    req.rider = rider;
    
    // Update last activity timestamp in Redis
    await redisSetAsync(`lastActivity:${user.phone}`, currentTime, 'EX', 3600);
    next();
  } catch (err) {
    logger.error(`JWT verification failed: ${err.message}`);
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Session expired',
        redirect: '/login',
        reason: 'Token has expired after 1 hour of inactivity'
      });
    }
    return res.status(403).json({ 
      error: 'Invalid token',
      redirect: '/login',
      reason: 'Token verification failed'
    });
  }
};

const MICRO_ADDONS = {
    "Rain Delay Coverage": { hptCost: 5, hbarCost: 0.1, duration: "24h" },
    "Flat Tire Fix": { hptCost: 10, hbarCost: 0.2, duration: "24h" },
};

function hederaToEvmAddress(accountIdStr) {
  const [shard, realm, account] = accountIdStr.split('.').map(Number);
  if (shard !== 0 || realm !== 0) {
    logger.warn(`Non-standard shard/realm detected: ${accountIdStr}`);
  }
  const accountHex = account.toString(16).padStart(40, '0');
  const evmAddress = `0x${accountHex}`;
  return evmAddress;
}
  
// Helper function to calculate Safe Rider Score
async function calculateSafeRiderScore(phone) {
    const policies = await db.collection('policies').find({ riderPhone: phone }).toArray();
    const claims = await db.collection('claims').find({ riderPhone: phone }).toArray();

    const activePolicies = policies.filter(p => new Date(p.expiryDate) > new Date()).length;
    const baseScore = 50; // Starting score
    const policyBonus = activePolicies * 10; // 10 points per active policy
    const claimPenalty = claims.length * 5; // -5 points per claim

    return Math.min(100, Math.max(0, baseScore + policyBonus - claimPenalty));
}

// Centralized Error Handler
const errorHandler = (err, req, res, next) => {
  logger.error(`Unhandled error: ${err.stack}`);
  res.status(500).json({ error: 'Internal server error' });
};
app.use(errorHandler);

// M-Pesa Auth Token with Caching
async function getMpesaToken() {
  const cacheKey = 'mpesa_token';
  let token = await redisGetAsync(cacheKey);
  if (!token) {
    try {
      const auth = Buffer.from(`${mpesaConsumerKey}:${mpesaConsumerSecret}`).toString('base64');
      const response = await axios.get(`${mpesaBaseUrl}/oauth/v1/generate?grant_type=client_credentials`, {
        headers: { Authorization: `Basic ${auth}` },
        timeout: 5000,
      });
      token = response.data.access_token;
      await redisSetAsync(cacheKey, token, 'EX', 3600);
      logger.info('M-Pesa token fetched and cached');
    } catch (error) {
      logger.error(`Failed to get M-Pesa token: ${error.message}`);
      throw error;
    }
  }
  return token;
}

// Existing Helper Functions (Enhanced)
const requireAuth = async (req, res, next) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone number required' });

  const rider = await db.collection('riders').findOne({ phone });
  if (!rider || !rider.accountId) {
    return res.status(401).json({ 
      error: 'Unauthorized: Rider not registered',
      redirect: '/login'
    });
  }
  req.rider = rider;
  next();
};

const validatePolicyInputs = (phone, plan, protectionType, premiumHbar) => {
  const phoneRegex = /^\+254\d{9}$/;
  if (!phoneRegex.test(phone)) throw new Error('Invalid phone number format. Expected: +254xxxxxxxxx');
  if (!['Daily', 'Weekly', 'Monthly'].includes(plan)) throw new Error('Invalid plan');
  if (!['rider', 'bike'].includes(protectionType)) throw new Error('Invalid protection type');
  const premium = parseFloat(premiumHbar);
  if (isNaN(premium) || premium <= 0) throw new Error('Invalid premiumHbar');
  return premium;
};

async function convertKshToHbar(amountKsh) {
  const cacheKey = `ksh_to_hbar_${amountKsh}`;
  let hbarAmount = await redisGetAsync(cacheKey);
  if (!hbarAmount) {
    try {
      const response = await axios.get('https://api.coinbase.com/v2/exchange-rates?currency=HBAR', { timeout: 5000 });
      const hbarToUsd = parseFloat(response.data.data.rates.USD);
      const usdToKsh = 129;
      hbarAmount = amountKsh * (1 / (hbarToUsd * usdToKsh));
      await redisSetAsync(cacheKey, hbarAmount, 'EX', 3600);
      logger.info(`Converted KSh ${amountKsh} to ${hbarAmount} HBAR`);
    } catch (error) {
      logger.error(`Conversion failed: ${error.message}`);
      throw error;
    }
  }
  return parseFloat(hbarAmount);
}

async function createRiderWallet(phone) {
  try {
    const riderPrivateKey = PrivateKey.generateED25519();
    const tx = await new AccountCreateTransaction()
      .setKey(riderPrivateKey)
      .setInitialBalance(new Hbar(100))
      .execute(client);
    const receipt = await tx.getReceipt(client);
    const riderAccountId = receipt.accountId.toString();

    await db.collection('riders').updateOne(
      { phone },
      { $set: { accountId: riderAccountId, privateKey: riderPrivateKey.toString() } },
      { upsert: true }
    );

    logger.info(`Wallet created for ${phone}: ${riderAccountId}`);
    return riderAccountId;
  } catch (error) {
    logger.error(`Wallet creation failed for ${phone}: ${error.message}`);
    throw error;
  }
}

async function associateToken(riderAccountId, tokenId, riderPrivateKey) {
  const tx = await new TokenAssociateTransaction()
    .setAccountId(riderAccountId)
    .setTokenIds([tokenId])
    .freezeWith(client)
    .sign(riderPrivateKey)
    .then((tx) => tx.execute(client));
  await tx.getReceipt(client);
  logger.info(`Token ${tokenId} associated with ${riderAccountId}`);
}

async function issueDefaultTestTokens(riderAccountId) {
  const defaultTokenAmount = 100;
  try {
    const accountInfo = await new AccountBalanceQuery().setAccountId(accountId).execute(client);
    const tokenBalance = accountInfo.tokens.get(premiumTokenId) || 0;
    if (tokenBalance < defaultTokenAmount) {
      throw new Error(`Operator account ${accountId} has insufficient HPT balance: ${tokenBalance}`);
    }

    const tx = await new TransferTransaction()
      .addTokenTransfer(premiumTokenId, accountId, -defaultTokenAmount)
      .addTokenTransfer(premiumTokenId, riderAccountId, defaultTokenAmount)
      .execute(client);
    const receipt = await tx.getReceipt(client);
    logger.info(`Issued ${defaultTokenAmount} HPT test tokens to ${riderAccountId}`);
    return defaultTokenAmount;
  } catch (error) {
    logger.error(`Failed to issue test tokens to ${riderAccountId}: ${error.message}`);
    throw error;
  }
}

async function payPremiumOnChain(phone, amountKsh) {
  const rider = await db.collection('riders').findOne({ phone });
  if (!rider || !rider.accountId) throw new Error('Rider not registered');

  const tokenAmount = amountKsh * 100;
  const tx = await new TransferTransaction()
    .addTokenTransfer(premiumTokenId, rider.accountId, -tokenAmount)
    .addTokenTransfer(premiumTokenId, accountId, tokenAmount)
    .execute(client);
  const receipt = await tx.getReceipt(client);
  logger.info(`Premium paid for ${phone}: ${amountKsh} KSh (${tokenAmount} HPT)`);

  await twilioClient.messages.create({
    from: process.env.TWILIO_WHATSAPP_NUMBER,
    to: `whatsapp:${phone}`,
    body: `Premium of KSh ${amountKsh} paid successfully. You’re insured for today!`,
  });
}

async function issuePolicyOnChain(riderAccountId, premiumHbar) {
  const contractExecTx = new ContractExecuteTransaction()
    .setContractId(ContractId.fromString(process.env.CLAIMS_CONTRACT_ID))
    .setGas(100000)
    .setFunction(
      'issuePolicy',
      new ContractFunctionParameters()
        .addAddress(AccountId.fromString(riderAccountId).toSolidityAddress())
        .addUint256(Math.floor(premiumHbar * 1e8))
    )
    .setPayableAmount(new Hbar(premiumHbar));

  const contractExecSubmit = await contractExecTx.execute(client);
  const receipt = await contractExecSubmit.getReceipt(client);

  if (receipt.status.toString() !== 'SUCCESS') {
    throw new Error(`Policy issuance failed on chain: ${receipt.status.toString()}`);
  }

  const transactionId = contractExecSubmit.transactionId.toString();
  logger.info(`Policy issued for ${riderAccountId} with ${premiumHbar} HBAR: ${transactionId}`);
  return transactionId;
}

async function triggerPayout(phone) {
  const rider = await db.collection('riders').findOne({ phone });
  if (!rider) throw new Error('Rider not registered');

  let evmAddress;
  try {
    evmAddress = AccountId.fromString(rider.accountId).toEvmAddress();
  } catch (e) {
    const accountNumber = AccountId.fromString(rider.accountId).num.toString(16);
    evmAddress = accountNumber.padStart(40, '0');
    logger.warn(`Manual EVM address conversion for ${rider.accountId}: ${evmAddress}`);
  }
  const formattedAddress = `0x${evmAddress}`;

  if (formattedAddress.length !== 42) {
    throw new Error(`Invalid EVM address length: ${formattedAddress}`);
  }

  const contractBalance = await new AccountBalanceQuery()
    .setAccountId(ContractId.fromString(claimsContractId))
    .execute(client);
  const balanceInHbar = contractBalance.hbars.toBigNumber().toNumber();
  if (balanceInHbar < 50) {
    const fundTx = await new TransferTransaction()
      .addHbarTransfer(accountId, new Hbar(-50))
      .addHbarTransfer(claimsContractId, new Hbar(50))
      .execute(client);
    await fundTx.getReceipt(client);
    logger.info(`Funded contract ${claimsContractId} with 50 HBAR`);
  }

  try {
    const tx = new ContractExecuteTransaction()
      .setContractId(claimsContractId)
      .setGas(200000)
      .setFunction("triggerPayout", new ContractFunctionParameters().addAddress(formattedAddress));
    const txResponse = await tx.execute(client);
    const receipt = await txResponse.getReceipt(client);

    if (receipt.status.toString() !== 'SUCCESS') {
      throw new Error(`Contract execution reverted: ${receipt.status.toString()}`);
    }

    logger.info(`Payout of 50 HBAR triggered to ${rider.accountId} (EVM: ${formattedAddress}) for ${phone}`);
    await twilioClient.messages.create({
      from: process.env.TWILIO_WHATSAPP_NUMBER,
      to: `whatsapp:${phone}`,
      body: `Claim approved! 50 HBAR sent to your wallet: ${rider.accountId}`,
    });
  } catch (error) {
    logger.error(`Contract execution failed for ${phone}: ${error.message}`);
    throw error;
  }
}

async function initiateMpesaPayment(phone, amountKsh, purpose) {
  const token = await getMpesaToken();
  const timestamp = new Date().toISOString().replace(/[-:.T]/g, '').slice(0, 14);
  const password = Buffer.from(`${mpesaShortcode}${mpesaPasskey}${timestamp}`).toString('base64');

  const response = await axios.post(
    `${mpesaBaseUrl}/mpesa/stkpush/v1/processrequest`,
    {
      BusinessShortCode: mpesaShortcode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Math.floor(amountKsh),
      PartyA: phone.replace('+', ''),
      PartyB: mpesaShortcode,
      PhoneNumber: phone.replace('+', ''),
      CallBackURL: callbackUrl,
      AccountReference: 'HashGuard',
      TransactionDesc: purpose,
    },
    { headers: { Authorization: `Bearer ${token}` }, timeout: 10000 }
  );
  return response.data;
}

// Enhanced Endpoints
app.post('/register', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone number required' });

  try {
    const existingRider = await db.collection('riders').findOne({ phone });
    if (existingRider && existingRider.accountId) {
      return res.status(400).json({ error: 'Phone already fully registered' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await db.collection('otps').updateOne(
      { phone },
      { $set: { otp, createdAt: new Date() } },
      { upsert: true }
    );

    try {
      await twilioClient.messages.create({
        from: process.env.TWILIO_WHATSAPP_NUMBER,
        to: `whatsapp:${phone}`,
        body: `Your HashGuard OTP is ${otp}. Reply with this to verify.`,
      });
      logger.info(`OTP sent to ${phone} via WhatsApp`);
    } catch (twilioError) {
      logger.warn(`Failed to send OTP via WhatsApp to ${phone}: ${twilioError.message}`);
    }

    res.json({ message: 'OTP sent to your WhatsApp or use the code below', otp });
  } catch (error) {
    logger.error(`Registration failed for ${phone}: ${error.message}`);
    res.status(500).json({ error: 'Failed to process registration' });
  }
});

app.post('/verify', async (req, res) => {
  const { phone, otp } = req.body;
  if (!phone || !otp) return res.status(400).json({ error: 'Phone and OTP required' });

  try {
    const storedOtp = await db.collection('otps').findOne({ phone });
    if (!storedOtp || storedOtp.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    await db.collection('riders').updateOne(
      { phone },
      { $setOnInsert: { phone } },
      { upsert: true }
    );

    await db.collection('otps').deleteOne({ phone });
    const token = jwt.sign({ phone }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'OTP verified', token });
  } catch (error) {
    logger.error(`Verification failed for ${phone}: ${error.message}`);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

app.post('/deposit/mpesa', authenticateToken, async (req, res) => {
  const { phone, amountKsh } = req.body;
  if (!phone || !amountKsh) return res.status(400).json({ error: 'Phone and amount required' });

  try {
    const rider = req.rider;
    const paymentResponse = await initiateMpesaPayment(phone, amountKsh, 'HBAR Deposit');
    const checkoutRequestId = paymentResponse.CheckoutRequestID;

    await db.collection('pending_payments').insertOne({
      checkoutRequestId,
      phone,
      amountKsh,
      type: 'hbar_deposit',
      status: 'pending',
      createdAt: new Date(),
    });

    res.json({ message: 'M-Pesa payment initiated', checkoutRequestId });
  } catch (error) {
    logger.error(`M-Pesa deposit failed for ${phone}: ${error.message}`);
    res.status(500).json({ error: 'Failed to initiate payment' });
  }
});

app.post('/credit-hbar', authenticateToken, async (req, res) => {
    const { phone, amount, sourceWallet, idempotencyKey } = req.body;
  
    if (!phone || !amount || !sourceWallet || !idempotencyKey) {
      return res.status(400).json({ error: 'Missing required fields: phone, amount, sourceWallet, and idempotencyKey are required' });
    }
  
    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be greater than 0' });
    }
  
    try {
      const rider = req.rider; // From authenticateToken middleware
      const riderAccountId = rider.accountId;
  
      // Check if idempotency key has been used
      const existingTx = await db.collection('transactions').findOne({ idempotencyKey });
      if (existingTx) {
        return res.status(409).json({ error: 'Duplicate transaction detected', transactionId: existingTx.transactionId });
      }
  
      // Validate source wallet balance using AccountBalanceQuery
      const sourceAccountId = sourceWallet.startsWith('0.0.') ? sourceWallet : `0.0.${sourceWallet}`;
      const balanceQuery = new AccountBalanceQuery()
        .setAccountId(sourceAccountId);
      const sourceBalance = await balanceQuery.execute(client);
      const sourceHbarBalance = sourceBalance.hbars.toBigNumber().toNumber();
  
      const feeBuffer = 0.1; // Buffer for transaction fees
      if (sourceHbarBalance < amount + feeBuffer) {
        return res.status(400).json({ error: `Insufficient HBAR in source wallet: ${sourceHbarBalance} available, ${amount + feeBuffer} needed` });
      }
  
      // Perform the HBAR transfer
      const transferTx = new TransferTransaction()
        .addHbarTransfer(sourceAccountId, new Hbar(-amount))
        .addHbarTransfer(riderAccountId, new Hbar(amount))
        .setTransactionMemo(`Deposit of ${amount} HBAR from ${sourceWallet} to ${riderAccountId}`);
  
      // Assuming the rider's private key is available (for signing); adjust if using a different signing method
      const riderPrivateKey = PrivateKey.fromString(rider.privateKey); // Ensure this is securely stored
      const signedTx = await transferTx.freezeWith(client).sign(riderPrivateKey);
      const txResponse = await signedTx.execute(client);
      const txReceipt = await txResponse.getReceipt(client);
      const transactionId = txResponse.transactionId.toString();
  
      if (txReceipt.status.toString() !== 'SUCCESS') {
        throw new Error(`Transaction failed with status: ${txReceipt.status}`);
      }
  
      // Record the transaction
      const transactionRecord = {
        phone,
        type: 'deposit',
        amount,
        sourceWallet,
        destinationWallet: riderAccountId,
        transactionId,
        idempotencyKey,
        status: 'SUCCESS',
        timestamp: new Date().toISOString(),
      };
      await db.collection('transactions').insertOne(transactionRecord);
  
      // Notify via WhatsApp (assuming Twilio setup)
      await twilioClient.messages.create({
        from: process.env.TWILIO_WHATSAPP_NUMBER,
        to: `whatsapp:${phone}`,
        body: `Your deposit of ${amount} HBAR from ${sourceWallet} was successful! TxID: ${transactionId}`,
      });
  
      logger.info(`HBAR deposit successful for ${phone}: ${amount} HBAR from ${sourceWallet}`);
      res.json({
        message: 'HBAR deposit successful',
        transactionId,
      });
    } catch (error) {
      logger.error(`HBAR deposit failed for ${phone}: ${error.message}`);
      res.status(500).json({ error: `HBAR deposit failed: ${error.message}` });
    }
});

async function mapEvmToHedera(evmAddress) {
  const cacheKey = `evm_to_hedera_${evmAddress}`;
  let hederaAccountId = await redisGetAsync(cacheKey);
  if (!hederaAccountId) {
    const mapping = await db.collection('wallet_mappings').findOne({ evmAddress });
    hederaAccountId = mapping?.hederaAccountId || null;
    if (hederaAccountId) {
      await redisSetAsync(cacheKey, hederaAccountId, 'EX', 3600);
    }
  }
  return hederaAccountId;
}

app.post('/register-complete', authenticateToken, async (req, res) => {
    const { phone, fullName, email, idNumber } = req.body;
  
    if (!phone || !fullName || !email || !idNumber) {
      return res.status(400).json({ error: 'All fields required' });
    }
  
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: 'Invalid email address' });
  
    const phoneRegex = /^\+254\d{9}$/;
    if (!phoneRegex.test(phone)) return res.status(400).json({ error: 'Invalid phone number format' });
  
    try {
      const rider = req.rider;
      if (rider.accountId) return res.status(400).json({ error: 'Phone already fully registered' });
  
      const riderAccountId = await createRiderWallet(phone);
      const updatedRider = await db.collection('riders').findOne({ phone });
      const riderPrivateKey = PrivateKey.fromString(updatedRider.privateKey);
      await associateToken(riderAccountId, premiumTokenId, riderPrivateKey);
  
      const riderId = `RIDER-${uuidv4()}`;
      await db.collection('riders').updateOne(
        { phone },
        {
          $set: {
            fullName: fullName.trim(),
            email: email.toLowerCase().trim(),
            idNumber: idNumber.trim(),
            riderId,
            accountId: riderAccountId,
          },
        }
      );
  
      // Attempt WhatsApp notification, but don’t fail the request if it doesn’t work
      try {
        await twilioClient.messages.create({
          from: process.env.TWILIO_WHATSAPP_NUMBER,
          to: `whatsapp:${phone}`,
          body: `Welcome ${fullName}! Your Rider ID is ${riderId}. Your wallet (${riderAccountId}) is ready.`,
        });
      } catch (twilioError) {
        logger.warn(`Failed to send WhatsApp notification to ${phone}: ${twilioError.message}`);
        // Continue execution instead of throwing an error
      }
  
      res.json({ message: 'Registration completed', wallet: riderAccountId, riderId });
    } catch (error) {
      logger.error(`Complete registration failed for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Failed to complete registration' });
    }
});

app.post('/policies', authenticateToken, async (req, res) => {
  const { phone, plan, protectionType, premiumHbar, page = 1, limit = 10 } = req.body;
  const rider = req.rider;

  if (plan && protectionType && premiumHbar) {
    try {
      const validatedPremiumHbar = validatePolicyInputs(phone, plan, protectionType, premiumHbar);
      const accountInfo = await new AccountBalanceQuery().setAccountId(rider.accountId).execute(client);
      const hbarBalance = accountInfo.hbars.toBigNumber().toNumber();
      const feeBuffer = 0.5;
      if (hbarBalance < validatedPremiumHbar + feeBuffer) {
        return res.status(400).json({ error: `Insufficient HBAR: ${hbarBalance} available, ${validatedPremiumHbar + feeBuffer} needed` });
      }

      const riderPrivateKey = PrivateKey.fromString(rider.privateKey);
      const paymentTx = await new TransferTransaction()
        .addHbarTransfer(rider.accountId, new Hbar(-validatedPremiumHbar))
        .addHbarTransfer(accountId, new Hbar(validatedPremiumHbar))
        .freezeWith(client)
        .sign(riderPrivateKey);
      const paymentResponse = await paymentTx.execute(client);
      const paymentReceipt = await paymentResponse.getReceipt(client);
      const paymentTransactionId = paymentResponse.transactionId.toString();

      const transactionId = await issuePolicyOnChain(rider.accountId, validatedPremiumHbar);
      const expiryMs = plan === 'Daily' ? 86400000 : plan === 'Weekly' ? 604800000 : 2592000000;
      const policy = {
        riderPhone: phone,
        riderAccountId: rider.accountId,
        plan,
        protectionType,
        hbarAmount: validatedPremiumHbar,
        paymentMethod: 'hbar',
        transactionId,
        paymentTransactionId,
        createdAt: new Date().toISOString(),
        expiryDate: new Date(Date.now() + expiryMs).toISOString(),
        active: true,
      };

      const result = await db.collection('policies').insertOne(policy);
      await twilioClient.messages.create({
        from: process.env.TWILIO_WHATSAPP_NUMBER,
        to: `whatsapp:${phone}`,
        body: `Your ${plan} ${protectionType} policy is active! Paid ${validatedPremiumHbar} HBAR. Expires: ${new Date(policy.expiryDate).toLocaleDateString()}. TxID: ${transactionId}`,
      });

      res.status(201).json({
        message: `Policy ${plan} ${protectionType} created`,
        policyId: result.insertedId.toString(),
        transactionId,
        paymentTransactionId,
      });
    } catch (error) {
      logger.error(`Policy creation failed for ${phone}: ${error.message}`);
      res.status(500).json({ error: `Failed to create policy: ${error.message}` });
    }
  } else if (phone) {
    try {
      const pageNum = parseInt(page, 10);
      const limitNum = parseInt(limit, 10);
      if (pageNum < 1 || limitNum < 1 || limitNum > 100) {
        return res.status(400).json({ error: 'Invalid page or limit' });
      }

      const totalPolicies = await db.collection('policies').countDocuments({ riderPhone: phone });
      const policies = await db.collection('policies')
        .find({ riderPhone: phone })
        .sort({ createdAt: -1 })
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum)
        .toArray();

      res.status(200).json({
        policies: policies.map((p) => ({
          _id: p._id.toString(),
          plan: p.plan,
          protectionType: p.protectionType,
          hbarAmount: p.hbarAmount,
          createdAt: p.createdAt,
          expiryDate: p.expiryDate,
          active: new Date(p.expiryDate) > new Date(),
          transactionId: p.transactionId,
          paymentTransactionId: p.paymentTransactionId,
        })),
        pagination: {
          currentPage: pageNum,
          totalPages: Math.ceil(totalPolicies / limitNum),
          totalPolicies,
        },
      });
    } catch (error) {
      logger.error(`Policy fetch failed for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Failed to fetch policies' });
    }
  } else {
    res.status(400).json({ error: 'Phone number required' });
  }
});

async function payPremiumWithHbar(phone, hbarAmount, plan) {
  const rider = await db.collection('riders').findOne({ phone });
  if (!rider || !rider.accountId) throw new Error('Rider not registered');

  const riderPrivateKey = PrivateKey.fromString(rider.privateKey);
  const accountInfo = await new AccountBalanceQuery().setAccountId(rider.accountId).execute(client);
  const hbarBalance = accountInfo.hbars.toBigNumber().toNumber();
  const feeBuffer = 0.1;

  if (hbarBalance < hbarAmount + feeBuffer) {
    throw new Error(`Insufficient HBAR: Available=${hbarBalance}, Needed=${hbarAmount + feeBuffer}`);
  }

  const tx = await new TransferTransaction()
    .addHbarTransfer(rider.accountId, new Hbar(-hbarAmount))
    .addHbarTransfer(accountId, new Hbar(hbarAmount))
    .freezeWith(client)
    .sign(riderPrivateKey);
  const txResponse = await tx.execute(client);
  const receipt = await txResponse.getReceipt(client);
  const transactionId = txResponse.transactionId.toString();

  const expiryDate = new Date(Date.now() + (plan === 'Daily' ? 86400000 : plan === 'Weekly' ? 604800000 : 2592000000));
  await db.collection('policies').insertOne({
    riderAccountId: rider.accountId,
    riderPhone: phone,
    hbarAmount,
    plan,
    transactionId,
    paymentMethod: 'hbar',
    createdAt: new Date(),
    expiryDate,
  });

  await twilioClient.messages.create({
    from: process.env.TWILIO_WHATSAPP_NUMBER,
    to: `whatsapp:${phone}`,
    body: `Your ${plan} policy payment of ${hbarAmount.toFixed(2)} HBAR was successful! Coverage active until ${expiryDate.toLocaleDateString()}.`,
  });

  return { transactionId, success: true };
}

app.post('/paypremium', authenticateToken, async (req, res) => {
  const { phone, policies, totalAmount, paymentMethod } = req.body;

  if (!phone || !policies || !totalAmount || !paymentMethod) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const rider = req.rider;
    if (paymentMethod === 'hbar') {
      const accountInfo = await new AccountBalanceQuery().setAccountId(rider.accountId).execute(client);
      const hbarBalance = accountInfo.hbars.toTinybars().toNumber() / 100000000;

      if (hbarBalance < totalAmount) {
        return res.status(400).json({ error: 'Insufficient HBAR balance' });
      }

      const results = [];
      for (const policy of policies) {
        const expiryMs = policy.plan === 'Daily' ? 86400000 : policy.plan === 'Weekly' ? 604800000 : 2592000000;
        const newPolicy = {
          riderPhone: phone,
          riderAccountId: rider.accountId,
          plan: policy.plan,
          protectionType: policy.protectionType,
          hbarAmount: policy.amount,
          paymentMethod: 'hbar',
          createdAt: new Date().toISOString(),
          expiryDate: new Date(Date.now() + expiryMs).toISOString(),
          active: true,
        };

        const result = await db.collection('policies').insertOne(newPolicy);
        results.push(result.insertedId);

        const riderPrivateKey = PrivateKey.fromString(rider.privateKey);
        const tx = await new TransferTransaction()
          .addHbarTransfer(rider.accountId, new Hbar(-policy.amount))
          .addHbarTransfer(accountId, new Hbar(policy.amount))
          .freezeWith(client)
          .sign(riderPrivateKey);
        const txResponse = await tx.execute(client);
        const receipt = await txResponse.getReceipt(client);
        const transactionId = txResponse.transactionId.toString();

        await db.collection('policies').updateOne(
          { _id: result.insertedId },
          { $set: { transactionId } }
        );
      }

      res.json({ success: true, policyIds: results.map(id => id.toString()) });
    } else {
      const paymentResponse = await initiateMpesaPayment(phone, totalAmount, 'Premium Payment');
      await db.collection('pending_payments').insertOne({
        checkoutRequestId: paymentResponse.CheckoutRequestID,
        phone,
        amountKsh: totalAmount,
        type: 'premium',
        status: 'pending',
        createdAt: new Date(),
      });
      res.json({ message: 'M-Pesa payment initiated', checkoutRequestId: paymentResponse.CheckoutRequestID });
    }
  } catch (error) {
    logger.error(`Premium payment failed: ${error.message}`);
    res.status(500).json({ error: 'Payment processing failed' });
  }
});

app.post('/get-claims', authenticateToken, async (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number is required' });
  
    try {
      const rider = req.rider;
      const claims = await db.collection('claims')
        .find({ riderPhone: phone })
        .sort({ createdAt: -1 })
        .toArray();
  
      const policyIds = claims.map(claim => new ObjectId(claim.policy));
      const policies = await db.collection('policies')
        .find({ _id: { $in: policyIds } })
        .toArray();
  
      const policyMap = new Map(policies.map(p => [p._id.toString(), p]));
  
      res.json({
        success: true,
        claims: claims.map(claim => {
          const policy = policyMap.get(claim.policy.toString()) || {};
          return {
            _id: claim._id.toString(),
            claimId: claim.claimId,
            policy: claim.policy.toString(),
            premium: claim.premium || policy.hbarAmount || 0,
            effectiveDate: claim.effectiveDate || claim.createdAt,
            status: claim.status,
            createdAt: claim.createdAt,
            details: claim.details || 'N/A',
            imageUrl: claim.imageUrl || null,
            transactionId: claim.transactionId || null,
            paymentTransactionId: claim.paymentTransactionId || null,
            riderPhone: claim.riderPhone || phone,
            policyDetails: {
              plan: policy.plan || 'Unknown',
              protectionType: policy.protectionType || 'Unknown',
              active: policy.expiryDate ? new Date(policy.expiryDate) > new Date() : false,
            },
          };
        }),
        total: claims.length,
      });
    } catch (error) {
      res.status(500).json({ success: false, error: 'Failed to fetch claims' });
    }
  });
app.post('/callback', async (req, res) => {
  const callbackData = req.body.Body.stkCallback;
  const checkoutRequestId = callbackData.CheckoutRequestID;

  try {
    const payment = await db.collection('pending_payments').findOne({ checkoutRequestId });
    if (!payment) return res.status(404).json({ error: 'Payment not found' });

    if (callbackData.ResultCode !== 0) {
      await db.collection('pending_payments').updateOne(
        { checkoutRequestId },
        { $set: { status: 'failed', error: callbackData.ResultDesc } }
      );
      return res.json({ status: 'failed' });
    }

    const amountKsh = callbackData.CallbackMetadata.Item.find(i => i.Name === 'Amount').Value;
    const hbarAmount = await convertKshToHbar(amountKsh);
    const rider = await db.collection('riders').findOne({ phone: payment.phone });

    const tx = await new TransferTransaction()
      .addHbarTransfer(accountId, new Hbar(-hbarAmount))
      .addHbarTransfer(rider.accountId, new Hbar(hbarAmount))
      .execute(client);
    const receipt = await tx.getReceipt(client);

    await db.collection('pending_payments').updateOne(
      { checkoutRequestId },
      { $set: { status: 'completed', transactionId: tx.transactionId.toString() } }
    );

    res.json({ status: 'success' });
  } catch (error) {
    logger.error(`Callback processing failed: ${error.message}`);
    res.status(500).json({ error: 'Callback processing failed' });
  }
});


const claimStorage = multer.diskStorage({
    destination: './uploads/claims',
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
    },
});


const uploadClaim = multer({
    storage: claimStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit per file
    fileFilter: (req, file, cb) => {
      const filetypes = /jpeg|jpg|png/;
      const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
      const mimetype = filetypes.test(file.mimetype);
      if (extname && mimetype) return cb(null, true);
      cb(new Error('Only JPEG/PNG images are allowed'));
    },
  }).fields([
    { name: 'image', maxCount: 1 },
    { name: 'additionalEvidence', maxCount: 5 } // Up to 5 additional evidence files
]);

const storage = multer.diskStorage({
  destination: './uploads/claims',
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) return cb(null, true);
    cb(new Error('Only JPEG/PNG images are allowed'));
  },
});

app.use('/uploads/claims', express.static(path.join(__dirname, 'uploads/claims')));

app.post('/claims', authenticateToken, async (req, res) => {
  const { phone } = req.body;

  try {
    const rider = req.rider;
    const claims = await db.collection('claims')
      .find({ riderPhone: phone })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json({
      claims: claims.map(claim => ({
        ...claim,
        _id: claim._id.toString(),
        policy: claim.policy?.toString() || null,
      })),
    });
  } catch (error) {
    logger.error(`Failed to fetch claims: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch claims' });
  }
});

app.post('/all-claims', authenticateToken, async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone number required' });

  try {
    const rider = req.rider;
    const claims = await db.collection('claims')
      .find({ riderPhone: phone })
      .sort({ createdAt: -1 })
      .toArray();

    const activePolicies = await db.collection('policies')
      .find({ riderPhone: phone, expiryDate: { $gt: new Date().toISOString() } })
      .toArray();

    const enrichedClaims = await Promise.all(claims.map(async (claim) => {
      const policy = await db.collection('policies').findOne({ _id: new ObjectId(claim.policy) });
      return {
        ...claim,
        policyDetails: {
          plan: policy?.plan || 'Unknown',
          protectionType: policy?.protectionType || 'Unknown',
          active: activePolicies.some(p => p._id.toString() === claim.policy.toString()),
        },
        _id: claim._id.toString(),
      };
    }));

    res.status(200).json({ claims: enrichedClaims });
  } catch (error) {
    logger.error(`Failed to fetch claims: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch claims' });
  }
});

app.post('/claim', authenticateToken, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'additionalEvidence', maxCount: 5 }]), async (req, res) => {
    const { phone, policyId, details } = req.body;
    const rider = req.rider;
  
    try {
      // Validate inputs
      if (!phone || !policyId || !details) {
        logger.error(`Missing required fields: phone=${phone}, policyId=${policyId}, details=${details}`);
        return res.status(400).json({ error: 'Missing required fields' });
      }
  
      // Fetch policy
      const policy = await db.collection('policies').findOne({ _id: new ObjectId(policyId), riderPhone: phone });
      if (!policy || !policy.active || new Date(policy.expiryDate) < new Date()) {
        logger.error(`Invalid or expired policy: policyId=${policyId}, phone=${phone}`);
        return res.status(400).json({ error: 'Invalid or expired policy' });
      }
  
      // Handle file uploads
      const imageFile = req.files && req.files['image'] ? req.files['image'][0] : null;
      if (!imageFile) {
        logger.error('No image file uploaded');
        return res.status(400).json({ error: 'Image evidence is required' });
      }
  
      const additionalEvidenceFiles = req.files && req.files['additionalEvidence'] ? req.files['additionalEvidence'] : [];
      const imageUrl = `/uploads/claims/${imageFile.filename}`; // Ensure correct path
      const additionalEvidenceUrls = additionalEvidenceFiles.map(file => `/uploads/claims/${file.filename}`);
  
      // Create claim object with riderPhone
      const claim = {
        claimId: `CLM-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
        policy: policyId,
        riderPhone: phone, // Add phone number here
        premium: policy.hbarAmount || 0,
        effectiveDate: new Date().toISOString(),
        status: 'Pending',
        createdAt: new Date(),
        details,
        imageUrl,
        additionalEvidence: additionalEvidenceUrls,
        smartContractStatus: 'Pending',
      };
  
      // Insert claim into database
      const result = await db.collection('claims').insertOne(claim);
      logger.info(`Claim inserted: claimId=${claim.claimId}, policyId=${policyId}, riderPhone=${phone}`);
  
      // Validate environment variable
      if (!process.env.CLAIMS_CONTRACT_ID) {
        logger.error('CLAIMS_CONTRACT_ID not set in environment variables');
        throw new Error('Contract ID not configured');
      }
  
      // Execute smart contract
      const transaction = new ContractExecuteTransaction()
        .setContractId(process.env.CLAIMS_CONTRACT_ID)
        .setGas(1000000)
        .setFunction("submitClaim", new ContractFunctionParameters()
          .addString(rider.accountId)
          .addUint256(Math.floor((policy.hbarAmount || 0) * 100000000))
          .addString(claim.claimId));
  
      logger.info(`Executing transaction for claimId=${claim.claimId} with contractId=${process.env.CLAIMS_CONTRACT_ID}`);
      const txResponse = await transaction.execute(client);
      const receipt = await txResponse.getReceipt(client);
      claim.transactionId = txResponse.transactionId.toString();
      claim.smartContractStatus = receipt.status.toString();
  
      // Update claim with transaction details
      await db.collection('claims').updateOne(
        { _id: result.insertedId },
        { $set: { transactionId: claim.transactionId, smartContractStatus: claim.smartContractStatus } }
      );
      logger.info(`Claim updated with txId=${claim.transactionId}, status=${claim.smartContractStatus}`);
  
      res.status(201).json({ message: 'Claim submitted successfully', transactionId: claim.transactionId, smartContractStatus: claim.smartContractStatus });
    } catch (error) {
      logger.error(`Claim submission failed for phone=${phone}, policyId=${policyId}: ${error.message}, Stack: ${error.stack}`);
      res.status(500).json({ error: `Failed to process claim: ${error.message}` });
    }
});

app.post('/user-status', authenticateToken, async (req, res) => {
    const { phone } = req.body;
    try {
      const rider = req.rider;
      const policy = await db.collection('policies')
        .find({ riderAccountId: rider.accountId })
        .sort({ createdAt: -1 })
        .limit(1)
        .toArray();
  
      if (!policy.length) {
        return res.json({ active: false, premiumPaid: 0, lastPayment: "N/A", nextBill: 15, transactionId: "N/A" });
      }
  
      const latestPolicy = policy[0];
      const active = new Date(latestPolicy.expiryDate) > new Date();
      const createdAt = typeof latestPolicy.createdAt === 'string' 
        ? latestPolicy.createdAt 
        : latestPolicy.createdAt.toISOString();
  
      res.json({
        active,
        premiumPaid: latestPolicy.hbarAmount || 0, // Corrected field
        lastPayment: createdAt.split('T')[0],
        nextBill: 15,
        transactionId: latestPolicy.transactionId,
      });
    } catch (error) {
      logger.error(`Failed to fetch user status for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Failed to fetch user status' });
    }
  });

app.post('/payment-status', authenticateToken, async (req, res) => {
  const { phone, transactionId } = req.body;
  const transaction = await db.collection('transactions').findOne({ phone, transactionId });
  if (!transaction) return res.status(404).json({ error: 'Transaction not found' });
  res.json({ status: transaction.status, policyActive: transaction.policyActive });
});

app.post('/overview', authenticateToken, async (req, res) => {
    const { phone } = req.body;
  
    if (!phone) {
      return res.status(400).json({ error: 'Phone number is required' });
    }
  
    try {
      const rider = req.rider;
      const riderAccountId = rider.accountId;
  
      const riderData = await db.collection('riders').findOne({ phone });
      if (!riderData) {
        return res.status(404).json({ error: 'Rider not found' });
      }
  
      const balanceQuery = new AccountBalanceQuery().setAccountId(riderAccountId);
      const balance = await balanceQuery.execute(client);
      const walletBalance = balance.hbars.toBigNumber().toNumber();
      const hptBalance = balance.tokens.get(process.env.PREMIUM_TOKEN_ID)?.toNumber() || 0;
  
      // Fetch and map policies
      const policies = await db.collection('policies').find({ riderPhone: phone }).toArray();
      let policyActive = false;
      let nextPaymentDue = 'N/A';
      let nextBill = 0;
  
      if (policies.length > 0) {
        const activePolicy = policies[0];
        policyActive = activePolicy.active && new Date(activePolicy.expiryDate) > new Date();
        const expiryDate = new Date(activePolicy.expiryDate);
        nextPaymentDue = expiryDate instanceof Date && !isNaN(expiryDate)
          ? expiryDate.toISOString().split('T')[0]
          : 'Invalid Date';
        nextBill = activePolicy.hbarAmount || 1500;
      }
  
      const policyActivities = policies.map(policy => ({
        type: 'Policy',
        description: `${policy.plan} (${policy.protectionType})`,
        amount: policy.hbarAmount || 0,
        status: policy.active && new Date(policy.expiryDate) > new Date() ? 'Active' : 'Expired',
        date: policy.createdAt || new Date().toISOString(),
      }));
  
      // Fetch and map claims
      const claims = await db.collection('claims').find({ riderPhone: phone }).toArray();
      const claimActivities = claims.map(claim => ({
        type: 'Claim',
        description: claim.claimId || `Claim #${claim._id.toString().slice(-6)}`,
        amount: claim.premium || 0,
        status: claim.status || 'Pending',
        date: claim.createdAt || claim.effectiveDate || new Date().toISOString(),
      }));
  
      // Fetch and map transactions (deposits)
      const transactions = await db.collection('transactions')
        .find({ phone })
        .sort({ timestamp: -1 })
        .toArray();
      const transactionActivities = transactions.map(tx => ({
        type: tx.type || 'Deposit',
        description: tx.description || `${tx.type || 'Deposit'} #${tx._id.toString().slice(-6)}`,
        amount: tx.amount || 0,
        status: tx.status || 'Completed',
        date: tx.timestamp || new Date().toISOString(),
      }));
  
      // Combine and sort all activities by date (newest first)
      const activities = [...policyActivities, ...claimActivities, ...transactionActivities]
        .sort((a, b) => new Date(b.date) - new Date(a.date))
        .slice(0, 10); // Limit to 10 entries
  
      const overviewData = {
        riderId: riderData.riderId || 'N/A',
        fullName: riderData.fullName || 'User',
        email: riderData.email || '',
        idNumber: riderData.idNumber || '',
        wallet: riderAccountId,
        policyActive,
        nextPaymentDue,
        nextBill,
        walletBalance,
        hptBalance,
        activities,
      };
  
      console.log('overviewData:', JSON.stringify(overviewData, null, 2)); // Debug log
      res.json(overviewData);
    } catch (error) {
      logger.error(`Failed to fetch overview for ${phone}: ${error.message}`);
      res.status(500).json({ error: `Failed to fetch overview: ${error.message}` });
    }
});

app.post('/token-balance', authenticateToken, async (req, res) => {
  const { phone } = req.body;
  try {
    const rider = req.rider;
    const accountInfo = await new AccountBalanceQuery().setAccountId(rider.accountId).execute(client);
    const hptBalance = accountInfo.tokens.get(premiumTokenId) || 0;

    res.json({ hptBalance });
  } catch (error) {
    logger.error(`Failed to fetch token balance for ${phone}: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch token balance' });
  }
});

app.post('/wallet-balance', authenticateToken, async (req, res) => {
  const { phone } = req.body;
  try {
    const rider = req.rider;
    const accountInfo = await new AccountBalanceQuery().setAccountId(rider.accountId).execute(client);
    const tinybars = accountInfo.hbars.toTinybars().toNumber();
    const hbarBalance = tinybars / 100000000;
    const tokenBalance = accountInfo.tokens.get(premiumTokenId) || 0;

    res.json({ walletBalance: hbarBalance, hptBalance: tokenBalance });
  } catch (error) {
    logger.error(`Failed to fetch wallet balance for ${phone}: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch wallet balance' });
  }
});

app.post('/login-otp', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone number required' });

  try {
    const rider = await db.collection('riders').findOne({ phone });
    if (!rider) return res.status(400).json({ error: 'Phone not registered' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await twilioClient.messages.create({
      from: process.env.TWILIO_WHATSAPP_NUMBER,
      to: `whatsapp:${phone}`,
      body: `Your HashGuard Login OTP is ${otp}. Reply with this to verify.`,
    });

    await db.collection('otps').updateOne(
      { phone },
      { $set: { otp, createdAt: new Date() } },
      { upsert: true }
    );

    res.json({ message: 'OTP sent to your WhatsApp', otp });
  } catch (error) {
    logger.error(`Login OTP failed for ${phone}: ${error.message}`);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Health Check Endpoint
app.get('/health', async (req, res) => {
  try {
    await db.command({ ping: 1 });
    await redis.ping();
    res.json({ status: 'healthy', mongodb: 'connected', redis: 'connected' });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', error: error.message });
  }
});

// Transaction History Endpoint
app.get('/transactions/:phone', authenticateToken, async (req, res) => {
  const { phone } = req.params;
  try {
    const transactions = await db.collection('transactions')
      .find({ phone })
      .sort({ timestamp: -1 })
      .toArray();
    res.json(transactions);
  } catch (error) {
    logger.error(`Failed to fetch transactions for ${phone}: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// System Overview Endpoint
app.get('/system-overview', authenticateToken, async (req, res) => {
    try {
      const phone = req.rider.phone;
  
      // Fetch all policies
      const policies = await db.collection('policies')
        .find({})
        .sort({ createdAt: -1 })
        .toArray();
  
      // Fetch all claims
      const claims = await db.collection('claims')
        .find({})
        .sort({ createdAt: -1 })
        .toArray();
  
      // Fetch all deposits (assuming deposits are stored in 'transactions' with type 'deposit')
      const deposits = await db.collection('transactions')
        .find({ type: 'deposit' })
        .sort({ timestamp: -1 })
        .toArray();
  
      // Fetch recent system activities (e.g., from transactions)
      const recentActivities = await db.collection('transactions')
        .find({})
        .sort({ timestamp: -1 })
        .limit(10) // Limit to 10 recent activities
        .toArray();
  
      // Aggregate data
      const totalPolicies = policies.length;
      const totalClaims = claims.length;
      const totalPayouts = claims
        .filter(claim => claim.status === 'Approved' && claim.paymentTransactionId)
        .reduce((sum, claim) => sum + (claim.claimAmount || 50), 0); // Assuming 50 HBAR default payout if claimAmount not set
  
      const systemActivities = recentActivities.map(tx => ({
        type: tx.type || 'Unknown',
        date: new Date(tx.timestamp).toLocaleDateString(),
        amount: tx.amount || 0,
        user: tx.phone || 'N/A',
      }));
  
      res.json({
        totalPolicies,
        totalClaims,
        totalPayouts,
        policies: policies.map(p => ({
          _id: p._id.toString(),
          plan: p.plan,
          protectionType: p.protectionType,
          hbarAmount: p.hbarAmount,
          createdAt: p.createdAt,
          expiryDate: p.expiryDate,
          active: new Date(p.expiryDate) > new Date(),
          riderPhone: p.riderPhone,
        })),
        claims: claims.map(c => ({
          _id: c._id.toString(),
          claimId: c.claimId,
          policy: c.policy.toString(),
          status: c.status,
          createdAt: c.createdAt,
          amount: c.claimAmount || 50, // Default to 50 HBAR if not specified
          riderPhone: c.riderPhone,
        })),
        deposits: deposits.map(d => ({
          _id: d._id.toString(),
          amount: d.amount,
          sourceWallet: d.sourceWallet,
          transactionId: d.transactionId,
          timestamp: d.timestamp,
          phone: d.phone,
        })),
        recentActivities: systemActivities,
      });
    } catch (error) {
      logger.error(`Failed to fetch system overview: ${error.message}`);
      res.status(500).json({ error: 'Failed to fetch system overview' });
    }
});

// Logout Endpoint
app.post('/logout', authenticateToken, async (req, res) => {
  const { phone } = req.body;
  try {
    // Clear last activity timestamp
    await redis.del(`lastActivity:${phone}`);
    res.json({ message: 'Successfully logged out' });
  } catch (error) {
    logger.error(`Logout failed for ${phone}: ${error.message}`);
    res.status(500).json({ error: 'Failed to logout' });
  }
});

async function startServer() {
    try {
      logger.info('Starting server initialization...');
      logger.info(`Attempting to connect to MongoDB with URI: ${mongoUri.substring(0, 30)}...`);
      
      await connectToMongo();
      
      logger.info('MongoDB connected successfully');
      logger.info(`Initializing Hedera client for ${process.env.NODE_ENV === 'production' ? 'Mainnet' : 'Testnet'}`);
      logger.info(`Operator account: ${accountId}`);
      
      app.listen(port, () => {
        logger.info(`Server successfully started on port ${port}`);
        logger.info(`Environment: ${process.env.NODE_ENV}`);
        logger.info(`Hedera Network: ${process.env.NODE_ENV === 'production' ? 'Mainnet' : 'Testnet'}`);
      });
  
      process.on('unhandledRejection', (reason) => {
        logger.error(`Unhandled Rejection: ${reason.stack || reason}`);
      });
  
    } catch (error) {
      logger.error('Fatal error during server startup:');
      logger.error(error.stack || error.message);
      process.exit(1);
    }
  }

startServer();

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

const generateClaimId= () => {
    const rand = crypto.randomBytes(16).toString("hex")
    return `claim_id_${rand}`
}

// Config Validation
const requiredEnv = [
    'HEDERA_ACCOUNT_ID', 'HEDERA_PRIVATE_KEY', 'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN',
    'TWILIO_WHATSAPP_NUMBER', 'MPESA_CONSUMER_KEY', 'MPESA_CONSUMER_SECRET', 'MPESA_SHORTCODE',
    'MPESA_PASSKEY', 'CALLBACK_URL', 'NODE_ENV', 'PREMIUM_TOKEN_ID', 'CLAIMS_CONTRACT_ID',
    'MONGODB_URI'
];

for (const env of requiredEnv) {
  if (!process.env[env]) throw new Error(`Missing required env var: ${env}`);
}

const accountId = process.env.HEDERA_ACCOUNT_ID;
const privateKey = PrivateKey.fromString(process.env.HEDERA_PRIVATE_KEY);
const client = (process.env.NODE_ENV === 'production' ? Client.forMainnet() : Client.forTestnet())
  .setOperator(accountId, privateKey);

logger.info(`Client initialized with operator: ${accountId}`);
if (!accountId || !accountId.startsWith('0.0.')) {
throw new Error(`Invalid HEDERA_ACCOUNT_ID: ${accountId}`);
}
if (!privateKey) {
throw new Error('HEDERA_PRIVATE_KEY is invalid or missing');
}

logger.info(`Client network: ${(process.env.NODE_ENV === 'production' ? 'Mainnet' : 'Testnet')}, operator: ${client.operatorAccountId?.toString()}`);

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const app = express();
const port = process.env.PORT || 3000;
const premiumTokenId = TokenId.fromString(process.env.PREMIUM_TOKEN_ID);
const claimsContractId = process.env.CLAIMS_CONTRACT_ID;

const mongoUri = `${process.env.MONGODB_URI}`;
const mongoClient = new MongoClient(mongoUri);
let db;

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

// M-Pesa Config
const mpesaConsumerKey = process.env.MPESA_CONSUMER_KEY;
const mpesaConsumerSecret = process.env.MPESA_CONSUMER_SECRET;
const mpesaShortcode = process.env.MPESA_SHORTCODE;
const mpesaPasskey = process.env.MPESA_PASSKEY;
const callbackUrl = process.env.CALLBACK_URL;
const mpesaBaseUrl = process.env.NODE_ENV === 'production'
  ? 'https://api.safaricom.co.ke'
  : 'https://sandbox.safaricom.co.ke';

// In-memory DB (replace with Redis/MongoDB in prod)
const riders = new Map(); // phone -> { accountId, privateKey }
const otps = new Map();   // phone -> otp
const pendingPayments = new Map(); // checkoutRequestId -> { phone, amountKsh }

// Middleware
app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
}));
app.use(express.json());
app.use((req, res, next) => {
    if (!db) {
      logger.warn('Database not connected yet');
      return res.status(503).json({ error: 'Database not connected, please try again later' });
    }
    next();
});

// M-Pesa Auth Token
async function getMpesaToken() {
  try {
    const auth = Buffer.from(`${mpesaConsumerKey}:${mpesaConsumerSecret}`).toString('base64');
    const response = await axios.get(`${mpesaBaseUrl}/oauth/v1/generate?grant_type=client_credentials`, {
      headers: { Authorization: `Basic ${auth}` },
    });
    return response.data.access_token;
  } catch (error) {
    logger.error(`Failed to get M-Pesa token: ${error.message}`);
    throw error;
  }
}

const requireAuth = async (req, res, next) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });
  
    const rider = await db.collection('riders').findOne({ phone });
    if (!rider || !rider.accountId) {
      return res.status(401).json({ error: 'Unauthorized: Rider not registered' });
    }
    req.rider = rider; // Attach rider to request for downstream use
    next();
  };
  
  // Helper function to validate policy creation inputs
  const validatePolicyInputs = (phone, plan, protectionType, premiumHbar) => {
    const phoneRegex = /^\+254\d{9}$/;
    if (!phoneRegex.test(phone)) {
      throw new Error('Invalid phone number format. Expected: +254xxxxxxxxx');
    }
    if (!['Daily', 'Weekly', 'Monthly'].includes(plan)) {
      throw new Error('Invalid plan. Must be Daily, Weekly, or Monthly');
    }
    if (!['rider', 'bike'].includes(protectionType)) {
      throw new Error('Invalid protection type. Must be "rider" or "bike"');
    }
    const premium = parseFloat(premiumHbar);
    if (isNaN(premium) || premium <= 0) {
      throw new Error('Invalid premiumHbar. Must be a positive number');
    }
    return premium;
  };

// Mock KSh to HBAR conversion
async function convertKshToHbar(amountKsh) {
  try {
    const response = await axios.get('https://api.coinbase.com/v2/exchange-rates?currency=HBAR');
    const hbarToUsd = parseFloat(response.data.data.rates.USD);
    const usdToKsh = 129;
    const kshToHbar = 1 / (hbarToUsd * usdToKsh);
    const hbarAmount = amountKsh * kshToHbar;
    logger.info(`Converted KSh ${amountKsh} to ${hbarAmount} HBAR`);
    return hbarAmount;
  } catch (error) {
    logger.error(`Conversion failed: ${error.message}`);
    throw error;
  }
}

async function createRiderWallet(phone) {
    try {
      const riderPrivateKey = PrivateKey.generateED25519();
      const tx = await new AccountCreateTransaction()
        .setKey(riderPrivateKey)
        .setInitialBalance(new Hbar(1))
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

// async function ensureOperatorTokenAssociation() {
//     try {
//       // Check if the operator account is already associated with the token
//       const accountInfo = await new AccountBalanceQuery()
//         .setAccountId(accountId)
//         .execute(client);
      
//       const tokenBalance = accountInfo.tokens.get(premiumTokenId);
//       if (tokenBalance !== undefined) {
//         logger.info(`Operator account ${accountId} is already associated with token ${premiumTokenId}`);
//         return;
//       }
  
//       // If not associated, associate the token
//       const tx = await new TokenAssociateTransaction()
//         .setAccountId(accountId)
//         .setTokenIds([premiumTokenId])
//         .execute(client);
//       await tx.getReceipt(client);
//       logger.info(`Operator account ${accountId} associated with token ${premiumTokenId}`);
//     } catch (error) {
//       logger.error(`Failed to associate operator with token ${premiumTokenId}: ${error.message}`);
//       throw error;
//     }
// }

// async function mintTestTokens(amount) {
//     try {
//       const tx = await new TokenMintTransaction()
//         .setTokenId(premiumTokenId)
//         .setAmount(amount)
//         .execute(client);
//       const receipt = await tx.getReceipt(client);
//       logger.info(`Minted ${amount} HPT to operator account ${accountId}`);
//     } catch (error) {
//       logger.error(`Failed to mint HPT tokens: ${error.message}`);
//       throw error;
//     }
// }

// async function issueDefaultTestHbar(riderAccountId) {
//     const defaultHbarAmount = 10; // 10 HBAR for testing
//     try {
//       // Check operator's HBAR balance
//       const accountInfo = await new AccountBalanceQuery()
//         .setAccountId(accountId)
//         .execute(client);
      
//       // Fix the HBAR balance conversion
//       const hbarBalance = accountInfo.hbars.toBigNumber().toString();
      
//       if (parseFloat(hbarBalance) < defaultHbarAmount) {
//         throw new Error(`Operator account ${accountId} has insufficient HBAR balance: ${hbarBalance}`);
//       }
  
//       const tx = await new TransferTransaction()
//         .addHbarTransfer(accountId, new Hbar(-defaultHbarAmount))
//         .addHbarTransfer(riderAccountId, new Hbar(defaultHbarAmount))
//         .execute(client);
//       const receipt = await tx.getReceipt(client);
//       logger.info(`Issued ${defaultHbarAmount} HBAR test tokens to ${riderAccountId}`);
//       return defaultHbarAmount;
//     } catch (error) {
//       logger.error(`Failed to issue test HBAR to ${riderAccountId}: ${error.message}`);
//       throw error;
//     }
// }

// New function to issue default test tokens
async function issueDefaultTestTokens(riderAccountId) {
    const defaultTokenAmount = 100;
    try {
      // Check operator's token balance
      const accountInfo = await new AccountBalanceQuery()
        .setAccountId(accountId)
        .execute(client);
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
          .addUint256(Math.floor(premiumHbar * 1e8)) // Convert HBAR to tinybars
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
  
    // Convert Hedera Account ID to EVM address
    const hederaAccountId = AccountId.fromString(rider.accountId);
    let evmAddress;
    try {
      evmAddress = hederaAccountId.toEvmAddress();
    } catch (e) {
      const accountNumber = hederaAccountId.num.toString(16);
      evmAddress = accountNumber.padStart(40, '0');
      logger.warn(`Falling back to manual EVM address conversion for ${rider.accountId}: ${evmAddress}`);
    }
    const formattedAddress = `0x${evmAddress}`;
  
    if (formattedAddress.length !== 42) {
      throw new Error(`Invalid EVM address length: ${formattedAddress} (expected 42 characters)`);
    }
  
    // Check contract balance
    const contractBalance = await new AccountBalanceQuery()
      .setAccountId(ContractId.fromString(claimsContractId))
      .execute(client);
    const balanceInHbar = contractBalance.hbars.toBigNumber().toNumber();
    logger.info(`Contract balance: ${balanceInHbar} HBAR`);
    if (balanceInHbar < 50) {
      logger.warn(`Insufficient contract balance: ${balanceInHbar} HBAR (required: 50 HBAR)`);
      const fundTx = await new TransferTransaction()
        .addHbarTransfer(accountId, new Hbar(-50))
        .addHbarTransfer(claimsContractId, new Hbar(50))
        .execute(client);
      await fundTx.getReceipt(client);
      logger.info(`Funded contract ${claimsContractId} with 50 HBAR`);
    }
  
    // Execute the contract call
    try {
      const tx = new ContractExecuteTransaction()
        .setContractId(claimsContractId)
        .setGas(200000) // Increased gas limit
        .setFunction("triggerPayout", new ContractFunctionParameters().addAddress(formattedAddress));
  
      const txResponse = await tx.execute(client);
      const receipt = await txResponse.getReceipt(client);
  
      if (receipt.status.toString() !== 'SUCCESS') {
        throw new Error(`Contract execution reverted with status: ${receipt.status.toString()}`);
      }
  
      const record = await txResponse.getRecord(client);
      const contractResult = record.contractFunctionResult;
      if (contractResult) {
        logger.info(`Contract result: ${contractResult.toString()}`);
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

// M-Pesa STK Push
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
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return response.data;
}

// Endpoints
app.post('/register', async (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });
  
    try {
      const existingRider = await db.collection('riders').findOne({ phone });
      if (existingRider && existingRider.accountId) {
        return res.status(400).json({ error: 'Phone already fully registered' });
      }
  
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await twilioClient.messages.create({
        from: process.env.TWILIO_WHATSAPP_NUMBER,
        to: `whatsapp:${phone}`,
        body: `Your HashGuard OTP is ${otp}. Reply with this to verify.`,
      });
      
      console.log(otp)
  
      await db.collection('otps').updateOne(
        { phone },
        { $set: { otp, createdAt: new Date() } },
        { upsert: true }
      );
  
      logger.info(`OTP sent to ${phone}`);
      res.json({ message: 'OTP sent to your WhatsApp' });
    } catch (error) {
      logger.error(`Registration failed for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Failed to send OTP' });
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
  
      logger.info(`OTP verified for ${phone}`);
      res.json({ message: 'OTP verified, proceed to complete registration' });
    } catch (error) {
      logger.error(`Verification failed for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Failed to verify OTP' });
    }
});

app.post('/credit-hbar', async (req, res) => {
    const { phone, amount } = req.body;
    if (!phone || !amount) return res.status(400).json({ error: 'Phone and amount required' });

    try {
        const rider = await db.collection('riders').findOne({ phone });
        if (!rider || !rider.accountId) return res.status(400).json({ error: 'Rider not registered' });

        const tx = await new TransferTransaction()
            .addHbarTransfer(accountId, new Hbar(-amount))  // Deduct from operator
            .addHbarTransfer(rider.accountId, new Hbar(amount))  // Credit rider
            .execute(client);
        
        const receipt = await tx.getReceipt(client);

        // Update rider's balance in database
        const accountInfo = await new AccountBalanceQuery()
            .setAccountId(rider.accountId)
            .execute(client);
        
        await db.collection('riders').updateOne(
            { phone },
            { $set: { hbarBalance: accountInfo.hbars.toTinybars().toNumber() } }
        );

        res.json({ 
            message: `${amount} HBAR credited successfully`,
            transactionId: tx.transactionId.toString()
        });
    } catch (error) {
        logger.error(`Failed to credit HBAR to ${phone}: ${error.message}`);
        res.status(500).json({ error: 'Failed to credit HBAR' });
    }
});
  
app.post('/register-complete', async (req, res) => {
    const { phone, fullName, email, idNumber } = req.body;
  
    // Input validation
    if (!phone || !fullName || !email || !idNumber) {
      logger.warn(`Registration attempt with missing fields: ${JSON.stringify(req.body)}`);
      return res.status(400).json({ error: 'All fields (phone, fullName, email, idNumber) are required' });
    }
  
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      logger.warn(`Invalid email format: ${email}`);
      return res.status(400).json({ error: 'Invalid email address' });
    }
  
    const phoneRegex = /^\+254\d{9}$/;
    if (!phoneRegex.test(phone)) {
      logger.warn(`Invalid phone format: ${phone}`);
      return res.status(400).json({ error: 'Invalid phone number format. Expected: +254xxxxxxxxx' });
    }
  
    try {
      const rider = await db.collection('riders').findOne({ phone });
      if (!rider) {
        logger.warn(`Phone not verified: ${phone}`);
        return res.status(400).json({ error: 'Phone not verified' });
      }
      if (rider.accountId) {
        logger.warn(`Phone already registered: ${phone}`);
        return res.status(400).json({ error: 'Phone already fully registered' });
      }
  
      const riderAccountId = await createRiderWallet(phone);
      const updatedRider = await db.collection('riders').findOne({ phone });
      const riderPrivateKey = PrivateKey.fromString(updatedRider.privateKey);
      await associateToken(riderAccountId, premiumTokenId, riderPrivateKey);
  
      // Generate a unique riderId using UUID
      const riderId = `RIDER-${uuidv4()}`;
  
      // Update rider with riderId and other details
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
  
      // Notify user about registration
      const message = `Welcome ${fullName}! Your Rider ID is ${riderId}. Your HashGuard wallet (${riderAccountId}) is ready.`;
      await twilioClient.messages.create({
        from: process.env.TWILIO_WHATSAPP_NUMBER,
        to: `whatsapp:${phone}`,
        body: message,
      });
  
      logger.info(`Registration completed for ${phone}: ${riderAccountId}, Rider ID: ${riderId}`);
      res.json({ message: 'Registration completed', wallet: riderAccountId, riderId });
    } catch (error) {
      logger.error(`Complete registration failed for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Failed to complete registration' });
    }
});

app.post('/policies', requireAuth, async (req, res) => {
    const { phone, plan, protectionType, premiumHbar, page = 1, limit = 10 } = req.body;
    const rider = req.rider; // From requireAuth middleware
  
    // Policy creation flow
    if (plan && protectionType && premiumHbar) {
      try {
        // Step 1: Validate inputs
        const validatedPremiumHbar = validatePolicyInputs(phone, plan, protectionType, premiumHbar);
  
        // Step 2: Check rider's HBAR balance
        const accountInfo = await new AccountBalanceQuery()
          .setAccountId(rider.accountId)
          .execute(client);
        const hbarBalance = accountInfo.hbars.toBigNumber().toNumber();
        const feeBuffer = 0.5; // Reserve for network fees
        if (hbarBalance < validatedPremiumHbar + feeBuffer) {
          logger.warn(`Insufficient HBAR balance for ${phone}: Available=${hbarBalance}, Needed=${validatedPremiumHbar + feeBuffer}`);
          return res.status(400).json({ error: `Insufficient HBAR balance. Available: ${hbarBalance}, Needed: ${validatedPremiumHbar + feeBuffer}` });
        }
  
        // Step 3: Transfer HBAR from rider to operator (payment)
        const riderPrivateKey = PrivateKey.fromString(rider.privateKey);
        const paymentTx = await new TransferTransaction()
          .addHbarTransfer(rider.accountId, new Hbar(-validatedPremiumHbar))
          .addHbarTransfer(accountId, new Hbar(validatedPremiumHbar))
          .freezeWith(client)
          .sign(riderPrivateKey);
        const paymentResponse = await paymentTx.execute(client);
        const paymentReceipt = await paymentResponse.getReceipt(client);
        if (paymentReceipt.status.toString() !== 'SUCCESS') {
          throw new Error(`HBAR payment failed: ${paymentReceipt.status.toString()}`);
        }
        const paymentTransactionId = paymentResponse.transactionId.toString();
        logger.info(`HBAR payment successful for ${phone}: ${validatedPremiumHbar} HBAR, TxID: ${paymentTransactionId}`);
  
        // Step 4: Issue policy on-chain (only if payment succeeds)
        const contractId = ContractId.fromString(process.env.CLAIMS_CONTRACT_ID); // Use your contract ID
        const transactionId = await issuePolicyOnChain(rider.accountId, validatedPremiumHbar);
        logger.info(`Policy issued on-chain for ${phone}: TxID ${transactionId}`);
  
        // Step 5: Create policy in MongoDB (only if on-chain succeeds)
        const expiryMs = plan === 'Daily' ? 86400000 : plan === 'Weekly' ? 604800000 : 2592000000;
        const policy = {
          riderPhone: phone,
          riderAccountId: rider.accountId,
          plan,
          protectionType,
          hbarAmount: validatedPremiumHbar,
          paymentMethod: 'hbar',
          transactionId, // On-chain transaction ID
          paymentTransactionId, // Payment transaction ID
          createdAt: new Date().toISOString(),
          expiryDate: new Date(Date.now() + expiryMs).toISOString(),
          active: true,
        };
  
        const result = await db.collection('policies').insertOne(policy);
        logger.info(`Policy created in MongoDB for ${phone}: ${result.insertedId}`);
  
        // Step 6: Notify rider
        await twilioClient.messages.create({
          from: process.env.TWILIO_WHATSAPP_NUMBER,
          to: `whatsapp:${phone}`,
          body: `Your ${plan} ${protectionType === 'rider' ? 'Rider' : 'Bike'} Protection policy is active! Paid ${validatedPremiumHbar} HBAR. Expires: ${new Date(policy.expiryDate).toLocaleDateString()}. TxID: ${transactionId}`,
        });
  
        res.status(201).json({
          message: `Policy ${plan} ${protectionType === 'rider' ? 'Rider' : 'Bike'} Protection created`,
          policyId: result.insertedId.toString(),
          transactionId,
          paymentTransactionId,
        });
      } catch (error) {
        logger.error(`Policy creation failed for ${phone}: ${error.message}`);
        if (error.message.includes('Insufficient HBAR')) {
          return res.status(400).json({ error: error.message });
        }
        if (error.message.includes('Invalid')) {
          return res.status(400).json({ error: error.message });
        }
        res.status(500).json({ error: `Failed to create policy: ${error.message}` });
      }
    }
    // Policy fetch flow
    else if (phone) {
      try {
        const pageNum = parseInt(page, 10);
        const limitNum = parseInt(limit, 10);
        if (pageNum < 1 || limitNum < 1 || limitNum > 100) {
          return res.status(400).json({ error: 'Invalid page or limit. Page >= 1, Limit 1-100' });
        }
  
        const totalPolicies = await db.collection('policies').countDocuments({ riderPhone: phone });
        const policies = await db.collection('policies')
          .find({ riderPhone: phone })
          .sort({ createdAt: -1 })
          .skip((pageNum - 1) * limitNum)
          .limit(limitNum)
          .toArray();
  
        const formattedPolicies = policies.map((p) => ({
          _id: p._id.toString(),
          plan: p.plan,
          protectionType: p.protectionType,
          hbarAmount: p.hbarAmount,
          createdAt: p.createdAt,
          expiryDate: p.expiryDate,
          active: new Date(p.expiryDate) > new Date(),
          transactionId: p.transactionId,
          paymentTransactionId: p.paymentTransactionId,
        }));
  
        res.status(200).json({
          policies: formattedPolicies,
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

// Remove the convertKshToHbar function since we won't need it
// async function convertKshToHbar(amountKsh) { ... } // Removed

async function payPremiumWithHbar(phone, hbarAmount, plan) {
    try {
      const rider = await db.collection('riders').findOne({ phone });
      if (!rider || !rider.accountId) throw new Error('Rider not registered');
  
      // Retrieve rider's private key from the database
      const riderPrivateKey = PrivateKey.fromString(rider.privateKey);
      if (!riderPrivateKey) throw new Error('Rider private key not found');
  
      const accountInfo = await new AccountBalanceQuery()
        .setAccountId(rider.accountId)
        .execute(client);
      
      const hbarBalance = accountInfo.hbars.toBigNumber().toNumber(); // Convert tinybars to HBAR
      const feeBuffer = 0.1; // Reserve for network fees
      logger.info(`Payment attempt for ${phone}: Balance=${hbarBalance} HBAR, Required=${hbarAmount} HBAR, Fees=${feeBuffer} HBAR`);
      
      if (hbarBalance < (hbarAmount + feeBuffer)) {
        throw new Error(`Insufficient HBAR balance: Available=${hbarBalance}, Needed=${hbarAmount + feeBuffer}`);
      }
  
      // Create and sign the transaction with the rider's private key
      const tx = new TransferTransaction()
        .addHbarTransfer(rider.accountId, new Hbar(-hbarAmount))
        .addHbarTransfer(accountId, new Hbar(hbarAmount));
  
      // Freeze the transaction and sign it with the rider's private key
      const signedTx = await tx.freezeWith(client).sign(riderPrivateKey);
  
      // Execute the signed transaction
      const txResponse = await signedTx.execute(client);
      const receipt = await txResponse.getReceipt(client);
      const transactionId = txResponse.transactionId.toString();
  
      // Create policy record
      const expiryDate = new Date(Date.now() + (plan === 'Daily' ? 86400000 : 
                             plan === 'Weekly' ? 604800000 : 2592000000));
      
      await db.collection('policies').insertOne({
        riderAccountId: rider.accountId,
        riderPhone: phone,
        hbarAmount,
        plan,
        transactionId,
        paymentMethod: 'hbar',
        createdAt: new Date(),
        expiryDate
      });
  
      // Send confirmation message
      await twilioClient.messages.create({
        from: process.env.TWILIO_WHATSAPP_NUMBER,
        to: `whatsapp:${phone}`,
        body: `Your ${plan} policy payment of ${hbarAmount.toFixed(2)} HBAR was successful! Coverage active until ${expiryDate.toLocaleDateString()}.`
      });
  
      logger.info(`HBAR payment processed for ${phone}: ${hbarAmount} HBAR for ${plan} plan`);
      return { transactionId, success: true };
    } catch (error) {
      logger.error(`HBAR payment failed for ${phone}: ${error.message}`);
      throw error;
    }
  }
  
  // Update /paypremium endpoint
// In your server code (index.ts)
app.post('/paypremium', async (req, res) => {
    try {
      const { phone, policies, totalAmount, paymentMethod } = req.body;
      
      if (!phone || !policies || !totalAmount || !paymentMethod) {
        return res.status(400).json({ error: 'Missing required fields' });
      }
  
      const rider = await db.collection('riders').findOne({ phone });
      if (!rider || !rider.accountId) {
        return res.status(404).json({ error: 'Rider not found' });
      }
  
      if (paymentMethod === 'hbar') {
        // Verify rider has sufficient HBAR balance
        const accountInfo = await new AccountBalanceQuery()
          .setAccountId(rider.accountId)
          .execute(client);
        
        const hbarBalance = accountInfo.hbars.toTinybars().toNumber() / 100000000; // Convert to HBAR
        
        if (hbarBalance < totalAmount) {
          return res.status(400).json({ error: 'Insufficient HBAR balance' });
        }
  
        // Process each policy
        const results = [];
        for (const policy of policies) {
          const expiryMs = policy.plan === 'Daily' ? 86400000 : 
                           policy.plan === 'Weekly' ? 604800000 : 2592000000;
          
          // Create policy record
          const newPolicy = {
            riderPhone: phone,
            riderAccountId: rider.accountId,
            plan: policy.plan,
            protectionType: policy.protectionType,
            hbarAmount: policy.amount,
            paymentMethod: 'hbar',
            createdAt: new Date().toISOString(),
            expiryDate: new Date(Date.now() + expiryMs).toISOString(),
            active: true
          };
  
          // Save to database
          const result = await db.collection('policies').insertOne(newPolicy);
          results.push(result.insertedId);
  
          // Transfer HBAR from rider to insurance account
          const riderPrivateKey = PrivateKey.fromString(rider.privateKey);
          const tx = await new TransferTransaction()
            .addHbarTransfer(rider.accountId, new Hbar(-policy.amount))
            .addHbarTransfer(accountId, new Hbar(policy.amount))
            .freezeWith(client)
            .sign(riderPrivateKey);
          
          const txResponse = await tx.execute(client);
          const receipt = await txResponse.getReceipt(client);
          const transactionId = txResponse.transactionId.toString();
  
          // Update policy with transaction ID
          await db.collection('policies').updateOne(
            { _id: result.insertedId },
            { $set: { transactionId } }
          );
        }
  
        return res.json({ 
          success: true,
          policyIds: results.map(id => id.toString())
        });
      } else {
        // M-Pesa payment flow remains the same
        // ... existing M-Pesa code ...
      }
    } catch (error) {
      logger.error(`Premium payment failed: ${error.message}`);
      res.status(500).json({ error: 'Payment processing failed' });
    }
  });

  app.post('/get-claims', async (req, res) => {
    const { phone } = req.body;
  
    // Validate input
    if (!phone) {
      return res.status(400).json({ error: 'Phone number is required' });
    }
  
    try {
      // Fetch claims from the claims collection
      const claims = await db.collection('claims')
        .find({ riderPhone: phone })
        .sort({ createdAt: -1 }) // Sort by creation date, newest first
        .toArray();
  
      // Return the claims data
      res.json({
        success: true,
        claims: claims.map(claim => ({
          _id: claim._id.toString(),
          claimId: claim.claimId,
          policy: claim.policy.toString(), // Convert ObjectId to string
          premium: claim.premium,
          effectiveDate: claim.effectiveDate,
          status: claim.status,
          createdAt: claim.createdAt,
          details: claim.details,
          imageUrl: claim.imageUrl,
          // Include additional fields if they exist
          claimAmount: claim.claimAmount || null,
          paymentTransactionId: claim.paymentTransactionId || null,
          transactionId: claim.transactionId || null,
        })),
        total: claims.length,
      });
    } catch (error) {
      logger.error(`Failed to fetch claims for ${phone}: ${error.message}`);
      res.status(500).json({ success: false, error: 'Failed to fetch claims' });
    }
  });

  app.post('/callback', async (req, res) => {
    const callbackData = req.body.Body.stkCallback;
    const checkoutRequestId = callbackData.CheckoutRequestID;
    
    if (!checkoutRequestId) {
      logger.error('Callback received without CheckoutRequestID');
      return res.status(400).json({ error: 'Missing CheckoutRequestID' });
    }
  
    try {
      const payment = await db.collection('pending_payments').findOne({ checkoutRequestId });
      if (!payment) {
        logger.error(`No pending payment found for ${checkoutRequestId}`);
        return res.status(404).json({ error: 'Payment not found' });
      }
  
      if (callbackData.ResultCode !== 0) {
        await db.collection('pending_payments').updateOne(
          { checkoutRequestId },
          { $set: { status: 'failed', error: callbackData.ResultDesc } }
        );
        return res.json({ status: 'failed' });
      }
  
      // Process successful payment
      const amount = callbackData.CallbackMetadata.Item.find(i => i.Name === 'Amount').Value;
      const receiptNumber = callbackData.CallbackMetadata.Item.find(i => i.Name === 'MpesaReceiptNumber').Value;
  
      await db.collection('pending_payments').updateOne(
        { checkoutRequestId },
        { $set: { status: 'completed', receiptNumber } }
      );
  
      // Create policy
      await db.collection('policies').insertOne({
        riderPhone: payment.phone,
        amount,
        plan: payment.plan,
        transactionId: receiptNumber,
        paymentMethod: 'mpesa',
        createdAt: new Date(),
        expiryDate: new Date(Date.now() + (payment.plan === 'Daily' ? 86400000 : 
                         payment.plan === 'Weekly' ? 604800000 : 2592000000))
      });
  
      res.json({ status: 'success' });
    } catch (error) {
      logger.error(`Callback processing failed: ${error.message}`);
      res.status(500).json({ error: 'Callback processing failed' });
    }
});

const storage = multer.diskStorage({
    destination: './uploads/claims', // Create this folder in your project
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
    },
  });
  const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
      const filetypes = /jpeg|jpg|png/;
      const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
      const mimetype = filetypes.test(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      cb(new Error('Only JPEG/PNG images are allowed'));
    },
});

app.use('/uploads/claims', express.static(path.join(__dirname, 'uploads/claims')));
// Get all claims for a rider
app.post('/claims', async (req, res) => {
    try {
      const { phone } = req.body;
      
      if (!phone) {
        return res.status(400).json({ error: 'Phone number is required' });
      }
  
      // Verify rider exists
      const rider = await db.collection('riders').findOne({ phone });
      if (!rider) {
        return res.status(404).json({ error: 'Rider not found' });
      }
  
      // Get all claims for this rider from the claims collection
      const claims = await db.collection('claims')
        .find({ riderPhone: phone })
        .sort({ createdAt: -1 }) // Newest first
        .toArray();

        console.log(claims)
  
      // Convert MongoDB ObjectId to string
      const formattedClaims = claims.map(claim => ({
        ...claim,
        _id: claim._id.toString(),
        policy: claim.policy?.toString() || null
      }));
  
      res.status(200).json({ claims: formattedClaims });
    } catch (error) {
      logger.error(`Failed to fetch claims: ${error.message}`);
      res.status(500).json({ error: 'Failed to fetch claims' });
    }
  });

// Add this endpoint to your server code
app.post('/all-claims', async (req, res) => {
    try {
      const { phone } = req.body;
      if (!phone) {
        return res.status(400).json({ error: 'Phone number required' });
      }
  
      // Verify the rider exists
      const rider = await db.collection('riders').findOne({ phone });
      if (!rider) {
        return res.status(404).json({ error: 'Rider not found' });
      }
  
      // Get all claims for this rider
      const claims = await db.collection('claims')
        .find({ riderPhone: phone })
        .sort({ createdAt: -1 }) // Sort by newest first
        .toArray();
  
      // Get active policies to check which claims are for active policies
      const activePolicies = await db.collection('policies')
        .find({ 
          riderPhone: phone,
          expiryDate: { $gt: new Date().toISOString() }
        })
        .toArray();
  
      // Enrich claims with policy information
      const enrichedClaims = await Promise.all(claims.map(async (claim) => {
        const policy = await db.collection('policies').findOne({ 
          _id: new ObjectId(claim.policy) 
        });
  
        return {
          ...claim,
          policyDetails: {
            plan: policy?.plan || 'Unknown',
            protectionType: policy?.protectionType || 'Unknown',
            active: activePolicies.some(p => p._id.toString() === claim.policy.toString())
          },
          _id: claim._id.toString()
        };
      }))
  
      res.status(200).json({ claims: enrichedClaims });
    } catch (error) {
      logger.error(`Failed to fetch claims: ${error.message}`);
      res.status(500).json({ error: 'Failed to fetch claims' });
    }
  });

  app.post('/claim', upload.single('image'), async (req, res) => {
    const { phone, policyId, details } = req.body; // claimAmount removed from required fields
    const image = req.file;
  
    // Validate inputs
    if (!phone || !policyId || !details || !image) {
      return res.status(400).json({ error: 'Missing required fields (phone, policyId, details, image)' });
    }
  
    try {
      // Step 1: Verify rider exists
      const rider = await db.collection('riders').findOne({ phone });
      if (!rider) {
        return res.status(404).json({ error: 'Rider not found' });
      }
  
      // Step 2: Verify policy exists and is active
      const policy = await db.collection('policies').findOne({ 
        _id: new ObjectId(policyId), 
        riderPhone: phone 
      });
  
      if (!policy) {
        const activePolicies = await db.collection('policies')
          .find({ 
            riderPhone: phone,
            active: true,
            expiryDate: { $gt: new Date().toISOString() }
          })
          .toArray();
  
        if (activePolicies.length === 0) {
          return res.status(400).json({ error: 'No active policies found. Please purchase a policy first.' });
        }
        return res.status(400).json({ error: 'Specified policy not found' });
      }
  
      if (!policy.active || new Date(policy.expiryDate) < new Date()) {
        return res.status(400).json({ error: 'Specified policy is inactive or expired' });
      }
  
      // Step 3: Derive claim amount from policy
      const claimAmountHbar = policy.hbarAmount || (policy.premiumPaid ? policy.premiumPaid / 12.9 : 0);
      if (!claimAmountHbar || claimAmountHbar <= 0) {
        return res.status(400).json({ error: 'Invalid claim amount derived from policy' });
      }
  
      // Step 4: Check rider's HBAR balance
      const accountInfo = await new AccountBalanceQuery()
        .setAccountId(rider.accountId)
        .execute(client);
      const hbarBalance = accountInfo.hbars.toBigNumber().toNumber();
      const feeBuffer = 0.1; // Reserve for network fees
  
      if (hbarBalance < claimAmountHbar + feeBuffer) {
        logger.warn(`Insufficient HBAR balance for ${phone}: Available=${hbarBalance}, Needed=${claimAmountHbar + feeBuffer}`);
        return res.status(400).json({ error: `Insufficient HBAR balance. Available: ${hbarBalance}, Needed: ${claimAmountHbar + feeBuffer}` });
      }
  
      // Step 5: Deduct claim amount from rider to operator
      const riderPrivateKey = PrivateKey.fromString(rider.privateKey);
      const paymentTx = await new TransferTransaction()
        .addHbarTransfer(rider.accountId, new Hbar(-claimAmountHbar)) // Deduct from rider
        .addHbarTransfer(accountId, new Hbar(claimAmountHbar)) // Credit to operator
        .freezeWith(client)
        .sign(riderPrivateKey);
      const paymentResponse = await paymentTx.execute(client);
      const paymentReceipt = await paymentResponse.getReceipt(client);
      if (paymentReceipt.status.toString() !== 'SUCCESS') {
        throw new Error(`Payment deduction failed: ${paymentReceipt.status.toString()}`);
      }
      const paymentTransactionId = paymentResponse.transactionId.toString();
      logger.info(`Claim payment deducted for ${phone}: ${claimAmountHbar} HBAR, TxID: ${paymentTransactionId}`);
  
      // Step 6: Create initial claim document
      const claim = {
        riderPhone: phone,
        policy: new ObjectId(policyId),
        premium: claimAmountHbar, // Use derived claim amount
        effectiveDate: policy.createdAt,
        status: 'Pending',
        claimId: generateClaimId(),
        createdAt: new Date().toISOString(),
        details,
        imageUrl: `/uploads/claims/${image.filename}`,
        claimAmount: claimAmountHbar,
        paymentTransactionId
      };
  
      // Step 7: Insert claim into database
      const result = await db.collection('claims').insertOne(claim);
      const claimId = result.insertedId;
  
      // Step 8: Perform payout transaction (operator to rider)
      const payoutTx = new TransferTransaction()
        .addHbarTransfer(accountId, new Hbar(-claimAmountHbar)) // Deduct from operator
        .addHbarTransfer(AccountId.fromString(rider.accountId), new Hbar(claimAmountHbar)); // Add to rider
      const payoutResponse = await payoutTx.execute(client);
      const payoutReceipt = await payoutResponse.getReceipt(client);
      const payoutTransactionId = payoutResponse.transactionId.toString();
  
      if (payoutReceipt.status.toString() !== 'SUCCESS') {
        throw new Error(`Payout failed: ${payoutReceipt.status.toString()}`);
      }
  
      // Step 9: Update claim with payout transaction ID
      await db.collection('claims').updateOne(
        { _id: claimId },
        { $set: { transactionId: payoutTransactionId, status: 'Processed' } }
      );
  
      // Step 10: Mark the policy as inactive after successful claim
      await db.collection('policies').updateOne(
        { _id: new ObjectId(policyId) },
        { $set: { active: false, claimedAt: new Date().toISOString() } } // Optionally track when it was claimed
      );
  
      // Step 11: Notify rider
      await twilioClient.messages.create({
        from: process.env.TWILIO_WHATSAPP_NUMBER,
        to: `whatsapp:${phone}`,
        body: `Your claim (${claim.claimId}) for ${claimAmountHbar} HBAR has been processed! Payout TxID: ${payoutTransactionId}`,
      });
  
      res.json({ 
        message: 'Claim submitted, payment deducted, and payout processed successfully',
        claimId: claim.claimId,
        id: claimId.toString(),
        paymentTransactionId,
        payoutTransactionId
      });
    } catch (error) {
      logger.error(`Claim submission failed for ${phone}: ${error.message}`);
      res.status(500).json({ error: error.message });
    }
  });


app.post('/user-status', async (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });
  
    try {
      const rider = await db.collection('riders').findOne({ phone });
      if (!rider || !rider.accountId) return res.status(400).json({ error: 'Rider not registered' });
  
      // Fetch the latest policy for the rider
      const policy = await db.collection('policies')
        .find({ riderAccountId: rider.accountId })
        .sort({ createdAt: -1 })
        .limit(1)
        .toArray();
  
      if (!policy.length) {
        return res.json({
          active: false,
          premiumPaid: 0,
          lastPayment: "N/A",
          nextBill: 15,
          transactionId: "N/A",
        });
      }
  
      const latestPolicy = policy[0];
      const active = new Date(latestPolicy.expiryDate) > new Date();
  
      res.json({
        active,
        premiumPaid: latestPolicy.premium,
        lastPayment: latestPolicy.createdAt.toISOString().split('T')[0],
        nextBill: 15, // Fixed for now, adjust based on your logic
        transactionId: latestPolicy.transactionId,
      });
    } catch (error) {
      logger.error(`Failed to fetch user status for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Failed to fetch user status' });
    }
});

app.post('/payment-status', async (req, res) => {
    const { phone, transactionId } = req.body;
    const transaction = await db.collection('transactions').findOne({ phone, transactionId });
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    res.json({ status: transaction.status, policyActive: transaction.policyActive });
});

app.post('/overview', async (req, res) => {
    const { phone } = req.body;
    if (!phone) {
      logger.warn('Overview request missing phone number');
      return res.status(400).json({ error: 'Phone number required' });
    }
  
    try {
      const rider = await db.collection('riders').findOne(
        { phone },
        { projection: { riderId: 1, accountId: 1, fullName: 1, email: 1, idNumber: 1 } }
      );
      if (!rider || !rider.accountId) {
        logger.warn(`Rider not registered: ${phone}`);
        return res.status(400).json({ error: 'Rider not registered' });
      }
  
      const policy = await db.collection('policies')
        .find({ riderAccountId: rider.accountId })
        .sort({ createdAt: -1 })
        .limit(1)
        .toArray();
  
      const policyActive = policy.length > 0 && new Date(policy[0].expiryDate) > new Date();
  
      const recentActivities = await db.collection('transactions')
        .find({ riderAccountId: rider.accountId })
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray();
  
      const accountInfo = await new AccountBalanceQuery()
        .setAccountId(rider.accountId)
        .execute(client);
      
      // Fix the HBAR balance conversion
      const hbarBalance = accountInfo.hbars.toBigNumber().toString();
  
      res.json({
        riderId: rider.riderId,
        fullName: rider.fullName,
        email: rider.email,
        idNumber: rider.idNumber,
        wallet: rider.accountId,
        policyActive,
        nextPaymentDue: policyActive ? policy[0].expiryDate.toISOString().split('T')[0] : "N/A",
        nextBill: 15,
        walletBalance: parseFloat(hbarBalance),
        hptBalance: accountInfo.tokens.get(premiumTokenId) || 0,
        recentActivities: recentActivities.map(tx => ({
          type: tx.type,
          date: tx.createdAt.toISOString().split('T')[0],
          amount: tx.amount || 0,
        })),
      });
    } catch (error) {
      logger.error(`Failed to fetch overview for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Failed to fetch overview' });
    }
});

app.post('/token-balance', async (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });
  
    try {
      const rider = await db.collection('riders').findOne({ phone });
      if (!rider || !rider.accountId) return res.status(400).json({ error: 'Rider not registered' });
  
      const accountInfo = await new AccountBalanceQuery()
        .setAccountId(rider.accountId)
        .execute(client);
  
      const hptBalance = accountInfo.tokens.get(premiumTokenId) || 0;
  
      res.json({ hptBalance });
    } catch (error) {
      logger.error(`Failed to fetch token balance for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Failed to fetch token balance' });
    }
});

app.post('/wallet-balance', async (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });
  
    try {
      const rider = await db.collection('riders').findOne({ phone });
      if (!rider || !rider.accountId) return res.status(400).json({ error: 'Rider not registered' });
  
      const accountInfo = await new AccountBalanceQuery()
        .setAccountId(rider.accountId)
        .execute(client);
      
      const tinybars = accountInfo.hbars.toTinybars().toNumber(); // Raw tinybars
      const hbarBalance = tinybars / 100000000; // Convert to HBAR
      const tokenBalance = accountInfo.tokens.get(premiumTokenId) || 0;
  
      logger.info(`Wallet balance for ${phone}: ${tinybars} tinybars, ${hbarBalance} HBAR, ${tokenBalance} HPT`);
  
      res.json({
        walletBalance: hbarBalance,
        hptBalance: tokenBalance
      });
    } catch (error) {
      logger.error(`Failed to fetch wallet balance for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Failed to fetch wallet balance' });
    }
});

app.post('/login-otp', async (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });

    try {
        // Check if the user exists
        const rider = await db.collection('riders').findOne({ phone });
        if (!rider) {
            return res.status(400).json({ error: 'Phone not registered. Please register first.' });
        }

        // Generate and send OTP
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

        logger.info(`Login OTP sent to ${phone}`);
        res.json({ message: 'OTP sent to your WhatsApp' });
    } catch (error) {
        logger.error(`Login OTP failed for ${phone}: ${error.message}`);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});

async function startServer() {
    try {
      await connectToMongo();
      app.listen(port, () => {
        logger.info(`Server running on port ${port} in ${process.env.NODE_ENV} mode (Hedera ${process.env.NODE_ENV === 'production' ? 'Mainnet' : 'Testnet'})`);
        process.on('unhandledRejection', (reason) => logger.error(`Unhandled Rejection: ${reason}`));
      });
    } catch (error) {
      logger.error('Failed to start server due to MongoDB connection error');
      process.exit(1);
    }
}

startServer();
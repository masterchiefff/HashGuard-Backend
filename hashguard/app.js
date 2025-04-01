require('dotenv').config();
const {
  Client,
  PrivateKey,
  AccountCreateTransaction,
  TokenAssociateTransaction,
  TransferTransaction,
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
const { MongoClient } = require('mongodb');
const cors = require('cors'); 
const { v4: uuidv4 } = require('uuid');

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
      .setContractId(contractId)
      .setGas(100000)
      .setFunction("issuePolicy", new ContractFunctionParameters()
        .addAddress(riderAccountId)
        .addUint256(premiumHbar * 1e8))
      .setPayableAmount(new Hbar(premiumHbar));
  
    const contractExecSubmit = await contractExecTx.execute(client);
    const receipt = await contractExecSubmit.getReceipt(client);
  
    if (receipt.status.toString() !== "SUCCESS") {
      throw new Error("Policy issuance failed on chain");
    }
  
    // Get the transaction ID
    const transactionId = contractExecSubmit.transactionId.toString();
  
    logger.info(`Policy issued for ${riderAccountId} with ${premiumHbar} HBAR: ${transactionId}`);
    return transactionId; // Return the transaction ID
  }

async function triggerPayout(phone) {
  const rider = await db.collection('riders').findOne({ phone });
  if (!rider) throw new Error('Rider not registered');

  const tx = await new ContractExecuteTransaction()
    .setContractId(claimsContractId)
    .setGas(100000)
    .setFunction("triggerPayout", new ContractFunctionParameters().addAddress(rider.accountId))
    .execute(client);
  const receipt = await tx.getReceipt(client);
  logger.info(`Payout of 50 HBAR triggered to ${rider.accountId} for ${phone}`);

  await twilioClient.messages.create({
    from: process.env.TWILIO_WHATSAPP_NUMBER,
    to: `whatsapp:${phone}`,
    body: `Claim approved! 50 HBAR sent to your wallet: ${rider.accountId}`,
  });
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

app.post('/policies', async (req, res) => {
    const { phone, page = 1, limit = 5 } = req.body;
    
    try {
      const rider = await db.collection('riders').findOne({ phone });
      if (!rider) {
        return res.status(404).json({ 
          error: 'Rider not found',
          policies: [],
          pagination: { totalPages: 0 }
        });
      }
  
      const totalPolicies = await db.collection('policies')
        .countDocuments({ riderAccountId: rider.accountId });
  
      const policies = await db.collection('policies')
        .find({ riderAccountId: rider.accountId })
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray();
  
      res.json({
        policies: policies.map(p => ({
          active: new Date(p.expiryDate) > new Date(),
          premiumPaid: p.premium,
          lastPayment: p.createdAt,
          expiryDate: p.expiryDate,
          transactionId: p.transactionId,
          plan: p.plan
        })),
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalPolicies / limit),
          totalPolicies
        }
      });
    } catch (error) {
      logger.error(`Policy fetch failed: ${error.message}`);
      res.status(500).json({ 
        error: 'Failed to fetch policies',
        policies: [],
        pagination: { totalPages: 0 }
      });
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
  app.post('/paypremium', async (req, res) => {
    const { phone, amount, plan, paymentMethod } = req.body;
    
    if (!phone || !amount || !plan) {
      return res.status(400).json({ error: 'Phone, amount, and plan are required' });
    }
  
    try {
      if (paymentMethod === 'hbar') {
        const hbarAmount = parseFloat(amount); // Amount is now in HBAR
        const result = await payPremiumWithHbar(phone, hbarAmount, plan);
        res.json({ 
          success: true,
          transactionId: result.transactionId,
          message: 'HBAR payment processed successfully'
        });
      } else {
        // M-Pesa payment (still in KSh)
        const amountKsh = parseFloat(amount);
        const token = await getMpesaToken();
        const timestamp = new Date().toISOString().replace(/[-:.T]/g, '').slice(0, 14);
        const password = Buffer.from(`${mpesaShortcode}${mpesaPasskey}${timestamp}`).toString('base64');
        const checkoutRequestId = `BODA-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  
        await db.collection('pending_payments').insertOne({
          checkoutRequestId,
          phone,
          amountKsh,
          plan,
          createdAt: new Date(),
          status: 'pending'
        });
  
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
            AccountReference: `BODA-${plan}`,
            TransactionDesc: `BodaBoda ${plan} Plan`,
            CheckoutRequestID: checkoutRequestId
          },
          { headers: { Authorization: `Bearer ${token}` } }
        );
  
        res.json({ 
          success: true,
          checkoutRequestId,
          ...response.data 
        });
      }
    } catch (error) {
      logger.error(`Payment initiation failed: ${error.message}`);
      res.status(500).json({ error: error.message || 'Payment initiation failed' });
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

app.post('/claim', async (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });
    const rider = await db.collection('riders').findOne({ phone });
    if (!rider || !rider.accountId) return res.status(400).json({ error: 'Rider not registered' });
  
    try {
      // Store the claim in MongoDB
      await db.collection('claims').insertOne({
        riderAccountId: rider.accountId,
        phone,
        status: 'Pending',
        effectiveDate: new Date().toISOString().split('T')[0],
        premium: 786.99, // Replace with actual premium amount
        policy: "Karisa's Apple Juju", // Replace with actual policy name
        createdAt: new Date(),
      });
  
      await triggerPayout(phone);
      res.json({ message: 'Payout triggered successfully' });
    } catch (error) {
      logger.error(`Payout failed for ${phone}: ${error.message}`);
      res.status(500).json({ error: 'Payout failed' });
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
const express = require('express');
const { 
    Client, 
    PrivateKey, 
    AccountId, 
    ContractExecuteTransaction, 
    ContractFunctionParameters, 
    AccountBalanceQuery, 
    TransactionReceiptQuery, 
    Status,
    ContractId,
    ContractCallQuery,
    Hbar 
} = require("@hashgraph/sdk");
const fetch = require('node-fetch');
require('dotenv').config();
const contractAbi = require('./artifacts/contracts/RegisterUser.sol/RegisterUser.json');
const AfricasTalking = require('africastalking'); // Add Africa's Talking SDK

const app = express();
app.use(express.json());

// Africa's Talking Configuration
const atCredentials = {
    apiKey: process.env.AT_API_KEY,
    username: process.env.AT_USERNAME
};
const africasTalking = AfricasTalking(atCredentials);
const sms = africasTalking.SMS;

// Hedera Configuration
function getConfig() {
    const requiredVars = ['OPERATOR_ID', 'OPERATOR_PVKEY', 'CONTRACT_ID', 'AT_USERNAME', 'AT_API_KEY'];
    const missingVars = requiredVars.filter(v => !process.env[v]);

    if (missingVars.length > 0) {
        throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
    }

    return {
        operatorId: AccountId.fromString(process.env.OPERATOR_ID),
        operatorKey: PrivateKey.fromString(process.env.OPERATOR_PVKEY),
        contractId: ContractId.fromString(process.env.CONTRACT_ID)
    };
}

const { operatorId, operatorKey, contractId } = getConfig();
const client = Client.forTestnet()
    .setOperator(operatorId, operatorKey)
    .setMaxAttempts(5);

// Verify contract and operator
async function verifySetup() {
    try {
        const balance = await new AccountBalanceQuery()
            .setAccountId(operatorId)
            .execute(client);
        console.log(`Operator balance: ${balance.hbars.toString()}`);
        console.log(`Connected to contract: ${contractId.toString()}`);
        return true;
    } catch (error) {
        throw new Error(`Setup verification failed: ${error.message}`);
    }
}

// Generate a 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
}

// Send OTP via Africa's Talking SMS
async function sendOTP(mobileNumber, otp) {const express = require('express');
    const { 
        Client, 
        PrivateKey, 
        AccountId, 
        ContractExecuteTransaction, 
        ContractFunctionParameters, 
        AccountBalanceQuery, 
        ContractCallQuery, 
        Hbar 
    } = require("@hashgraph/sdk");
    require('dotenv').config();
    const AfricasTalking = require('africastalking');
    
    // You'll need to generate this ABI from the MpesaInsurance contract compilation
    const contractAbi = require('./artifacts/contracts/RegisterUser.sol/RegisterUser.json');
    
    const app = express();
    app.use(express.json());
    
    // Africa's Talking Configuration
    const atCredentials = {
        apiKey: process.env.AT_API_KEY,
        username: process.env.AT_USERNAME
    };
    const africasTalking = AfricasTalking(atCredentials);
    const sms = africasTalking.SMS;
    const payments = africasTalking.PAYMENTS;
    
    // Hedera Configuration
    function getConfig() {
        const requiredVars = ['OPERATOR_ID', 'OPERATOR_PVKEY', 'CONTRACT_ID', 'AT_USERNAME', 'AT_API_KEY'];
        const missingVars = requiredVars.filter(v => !process.env[v]);
    
        if (missingVars.length > 0) {
            throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
        }
    
        return {
            operatorId: AccountId.fromString(process.env.OPERATOR_ID),
            operatorKey: PrivateKey.fromString(process.env.OPERATOR_PVKEY),
            contractId: ContractId.fromString(process.env.CONTRACT_ID)
        };
    }
    
    const { operatorId, operatorKey, contractId } = getConfig();
    const client = Client.forTestnet()
        .setOperator(operatorId, operatorKey)
        .setMaxAttempts(5);
    
    // Utility Functions
    async function verifySetup() {
        try {
            const balance = await new AccountBalanceQuery()
                .setAccountId(operatorId)
                .execute(client);
            console.log(`Operator balance: ${balance.hbars.toString()}`);
            console.log(`Connected to contract: ${contractId.toString()}`);
            return true;
        } catch (error) {
            throw new Error(`Setup verification failed: ${error.message}`);
        }
    }
    
    function generateOTP() {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }
    
    async function sendOTP(mobileNumber, otp) {
        try {
            const options = {
                to: [mobileNumber],
                message: `Your OTP is: ${otp}. It is valid for 5 minutes.`
            };
            const response = await sms.send(options);
            return response;
        } catch (error) {
            throw new Error(`Failed to send OTP: ${error.message}`);
        }
    }
    
    // Contract Interaction Functions
    async function registerMobileNumber(mobileNumber) {
        const tx = await new ContractExecuteTransaction()
            .setContractId(contractId)
            .setGas(200000)
            .setFunction("registerWallet",
                new ContractFunctionParameters()
                    .addString(mobileNumber))
            .freezeWith(client)
            .sign(operatorKey)
            .execute(client);
    
        const receipt = await tx.getReceipt(client);
        if (receipt.status.toString() !== "SUCCESS") {
            throw new Error(`Registration failed: ${receipt.status.toString()}`);
        }
    
        const otp = generateOTP();
        await sendOTP(mobileNumber, otp);
    
        return { transactionId: tx.transactionId.toString(), otp };
    }
    
    async function getWalletByMobileNumber(mobileNumber) {
        const query = new ContractCallQuery()
            .setContractId(contractId)
            .setGas(100000)
            .setFunction("mobileToWallet",
                new ContractFunctionParameters()
                    .addString(mobileNumber))
            .setQueryPayment(new Hbar(1));
    
        const result = await query.execute(client);
        return result.getAddress(0) || "0x0000000000000000000000000000000000000000";
    }
    
    async function depositViaMpesa(mobileNumber, amountKSH) {
        const tx = await new ContractExecuteTransaction()
            .setContractId(contractId)
            .setGas(300000)
            .setFunction("depositViaMpesa",
                new ContractFunctionParameters()
                    .addString(mobileNumber)
                    .addUint256(amountKSH))
            .freezeWith(client)
            .sign(operatorKey)
            .execute(client);
    
        const receipt = await tx.getReceipt(client);
        if (receipt.status.toString() !== "SUCCESS") {
            throw new Error(`Deposit failed: ${receipt.status.toString()}`);
        }
        return tx.transactionId.toString();
    }
    
    async function purchasePolicy(mobileNumber) {
        const tx = await new ContractExecuteTransaction()
            .setContractId(contractId)
            .setGas(400000)
            .setFunction("purchasePolicy",
                new ContractFunctionParameters()
                    .addString(mobileNumber))
            .freezeWith(client)
            .sign(operatorKey)
            .execute(client);
    
        const receipt = await tx.getReceipt(client);
        if (receipt.status.toString() !== "SUCCESS") {
            throw new Error(`Policy purchase failed: ${receipt.status.toString()}`);
        }
        
        // Get the tokenId from logs (implementation may vary based on Hedera's event handling)
        const record = await tx.getRecord(client);
        const tokenId = record.contractFunctionResult.getUint256(0); // Assuming return value is tokenId
        return { transactionId: tx.transactionId.toString(), tokenId: tokenId.toString() };
    }
    
    async function claimPolicy(mobileNumber, tokenId) {
        const tx = await new ContractExecuteTransaction()
            .setContractId(contractId)
            .setGas(300000)
            .setFunction("claimPolicy",
                new ContractFunctionParameters()
                    .addString(mobileNumber)
                    .addUint256(tokenId))
            .freezeWith(client)
            .sign(operatorKey)
            .execute(client);
    
        const receipt = await tx.getReceipt(client);
        if (receipt.status.toString() !== "SUCCESS") {
            throw new Error(`Claim failed: ${receipt.status.toString()}`);
        }
        return tx.transactionId.toString();
    }
    
    async function getBalance(mobileNumber) {
        const query = new ContractCallQuery()
            .setContractId(contractId)
            .setGas(100000)
            .setFunction("getBalance",
                new ContractFunctionParameters()
                    .addString(mobileNumber))
            .setQueryPayment(new Hbar(1));
    
        const result = await query.execute(client);
        return result.getUint256(0).toString();
    }
    
    // M-Pesa Payment Initiation
    async function initiateMpesaPayment(mobileNumber, amountKSH) {
        try {
            const paymentData = {
                productName: process.env.AT_PRODUCT_NAME || "InsurancePayment",
                phoneNumber: mobileNumber,
                currencyCode: "KES",
                amount: amountKSH,
                metadata: { mobileNumber }
            };
    
            const response = await payments.mobileCheckout(paymentData);
            return response;
        } catch (error) {
            throw new Error(`M-Pesa payment initiation failed: ${error.message}`);
        }
    }
    
    app.post('/auth/signup', async (req, res) => {
        try {
            const { mobileNumber } = req.body;
            if (!mobileNumber) throw new Error("Mobile number required");
    
            const { transactionId, otp } = await registerMobileNumber(mobileNumber);
            res.json({ success: true, transactionId, otp });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    app.get('/auth/wallet', async (req, res) => {
        try {
            const { mobileNumber } = req.query;
            if (!mobileNumber) throw new Error("Mobile number required");
    
            const walletAddress = await getWalletByMobileNumber(mobileNumber);
            res.json({ success: true, mobileNumber, walletAddress });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    app.post('/deposit', async (req, res) => {
        try {
            const { mobileNumber, amountKSH } = req.body;
            if (!mobileNumber || !amountKSH) throw new Error("Mobile number and amount required");
    
            // Initiate M-Pesa payment
            const paymentResponse = await initiateMpesaPayment(mobileNumber, amountKSH);
            if (paymentResponse.status !== "PendingConfirmation") {
                throw new Error("Payment initiation failed");
            }
    
            // Assuming payment is confirmed via callback/webhook, proceed to deposit
            const transactionId = await depositViaMpesa(mobileNumber, amountKSH);
            res.json({ success: true, transactionId, paymentStatus: paymentResponse.status });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    app.post('/policy/purchase', async (req, res) => {
        try {
            const { mobileNumber } = req.body;
            if (!mobileNumber) throw new Error("Mobile number required");
    
            const { transactionId, tokenId } = await purchasePolicy(mobileNumber);
            res.json({ success: true, transactionId, tokenId });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    app.post('/policy/claim', async (req, res) => {
        try {
            const { mobileNumber, tokenId } = req.body;
            if (!mobileNumber || !tokenId) throw new Error("Mobile number and tokenId required");
    
            const transactionId = await claimPolicy(mobileNumber, tokenId);
            res.json({ success: true, transactionId });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    app.get('/balance', async (req, res) => {
        try {
            const { mobileNumber } = req.query;
            if (!mobileNumber) throw new Error("Mobile number required");
    
            const balance = await getBalance(mobileNumber);
            res.json({ success: true, mobileNumber, balance });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    app.get('/health', async (req, res) => {
        try {
            const balance = await new AccountBalanceQuery()
                .setAccountId(operatorId)
                .execute(client);
            res.json({
                status: 'operational',
                operatorId: operatorId.toString(),
                contractId: contractId.toString(),
                balance: balance.hbars.toString()
            });
        } catch (error) {
            res.status(503).json({ success: false, error: error.message });
        }
    });
    
    // Start Server
    const PORT = process.env.PORT || 3000;
    async function startServer() {
        try {
            await verifySetup();
            app.listen(PORT, () => {
                console.log(`Server running on port ${PORT}`);
                console.log(`Using contract: ${contractId.toString()}`);
            });
        } catch (error) {
            console.error('Server failed to start:', error.message);
            process.exit(1);
        }
    }
    
    startServer();
    try {
        const options = {
            to: [mobileNumber],
            message: `Your OTP is: ${otp}. It is valid for 5 minutes.`
        };
        const response = await sms.send(options);
        return response;
    } catch (error) {
        throw new Error(`Failed to send OTP: ${error.message}`);
    }
}

// Register mobile number and send OTP
async function registerMobileNumber(mobileNumber) {
    try {
        const tx = new ContractExecuteTransaction()
            .setContractId(contractId)
            .setGas(200000)
            .setFunction("registerWallet",
                new ContractFunctionParameters()
                    .addString(mobileNumber))
            .freezeWith(client);

        const signedTx = await tx.sign(operatorKey);
        const txResponse = await signedTx.execute(client);
        const receipt = await txResponse.getReceipt(client);

        if (receipt.status !== Status.Success) {
            throw new Error(`Transaction failed with status: ${receipt.status.toString()}`);
        }

        // Generate and send OTP after successful registration
        const otp = generateOTP();
        await sendOTP(mobileNumber, otp);

        return {
            transactionId: txResponse.transactionId.toString(),
            status: receipt.status.toString(),
            otp // Return OTP for temporary storage or verification
        };
    } catch (error) {
        throw new Error(`Registration failed: ${error.message}`);
    }
}

// Retrieve wallet address by mobile number
async function getWalletByMobileNumber(mobileNumber) {
    try {
        const query = new ContractCallQuery()
            .setContractId(contractId)
            .setGas(100000)
            .setFunction("mobileToWallet",
                new ContractFunctionParameters()
                    .addString(mobileNumber))
            .setQueryPayment(new Hbar(1));

        const result = await query.execute(client);
        const walletAddress = result.getAddress(0);

        return {
            mobileNumber,
            walletAddress: walletAddress || "0x0000000000000000000000000000000000000000"
        };
    } catch (error) {
        throw new Error(`Failed to retrieve wallet: ${error.message}`);
    }
}

// API Endpoint for Registration with OTP
app.post('/auth/signup', async (req, res) => {
    try {
        const { mobileNumber } = req.body;
        if (!mobileNumber || typeof mobileNumber !== 'string') {
            return res.status(400).json({ 
                success: false,
                error: 'Valid mobileNumber string is required' 
            });
        }

        const result = await registerMobileNumber(mobileNumber);
        res.json({
            success: true,
            transactionId: result.transactionId,
            contractId: contractId.toString(),
            status: result.status,
            otp: result.otp // For testing; in production, store it securely
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// API Endpoint to Retrieve Wallet Address
app.get('/auth/wallet', async (req, res) => {
    try {
        const { mobileNumber } = req.query;
        if (!mobileNumber || typeof mobileNumber !== 'string') {
            return res.status(400).json({ 
                success: false,
                error: 'Valid mobileNumber string is required' 
            });
        }

        const result = await getWalletByMobileNumber(mobileNumber);
        res.json({
            success: true,
            mobileNumber: result.mobileNumber,
            walletAddress: result.walletAddress,
            contractId: contractId.toString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Health check
app.get('/health', async (req, res) => {
    try {
        const balance = await new AccountBalanceQuery()
            .setAccountId(operatorId)
            .execute(client);
        res.json({
            status: 'operational',
            operatorId: operatorId.toString(),
            contractId: contractId.toString(),
            balance: balance.hbars.toString()
        });
    } catch (error) {
        res.status(503).json({ 
            status: 'unavailable',
            error: error.message 
        });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
async function startServer() {
    try {
        await verifySetup();
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
            console.log(`Using contract: ${contractId.toString()}`);
        });
    } catch (error) {
        console.error('Server failed to start:', error.message);
        process.exit(1);
    }
}

startServer();
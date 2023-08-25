require('dotenv').config();
const express = require('express');
const Web3 = require('web3');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const basicAuth = require('express-basic-auth');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const mongoose = require('mongoose');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcrypt');
const redis = require('redis');
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const winston = require('winston');

const app = express();
const port = 3000;

// Configuração do Swagger
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Sua API',
            version: '1.0.0',
            description: 'Descrição da sua API'
        },
        servers: [
            {
                url: 'http://localhost:3000'
            }
        ]
    },
    apis: ['./nome-do-seu-arquivo.js']
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Configuração do Winston
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'nome-do-seu-servico' },
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

// Carregando variáveis de ambiente
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const WEB3_PROVIDER_URL = process.env.URL_DA_REDE_ETHEREUM;
const JWT_SECRET = 'your_jwt_secret';

// Configurando middlewares
app.use(bodyParser.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(cors({ origin: 'http://seu-dominio-aqui.com' }));
app.use(basicAuth({ users: { 'seuUsuario': 'suaSenha' }, challenge: true }));
app.use(passport.initialize());

// Middleware para proteger rotas com JWT
app.use(expressJwt({ secret: JWT_SECRET, algorithms: ['HS256'] }).unless({ path: ['/login', '/register'] }));

// Conexão com o MongoDB
mongoose.connect('mongodb://localhost:27017/yourDatabaseName', { useNewUrlParser: true, useUnifiedTopology: true });

// Modelo de usuário
const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
    permissions: [String]
});

UserSchema.methods.isValidPassword = function(password) {
    return bcrypt.compareSync(password, this.password);
};

const User = mongoose.model('User', UserSchema);

// Modelo de Transação
const TransactionSchema = new mongoose.Schema({
    txHash: String,
    from: String,
    to: String,
    value: Number,
    method: String,
    timestamp: Date,
    status: String,
    errorMessage: String
});

const Transaction = mongoose.model('Transaction', TransactionSchema);

// Configuração do Passport
passport.use(new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: JWT_SECRET
}, (jwtPayload, done) => {
    User.findById(jwtPayload.id, (err, user) => {
        if (err) return done(err, false);
        if (user) return done(null, user);
        return done(null, false);
    });
}));

// Rotas de Registro e Login
app.post('/register', (req, res) => {
    const hashedPassword = bcrypt.hashSync(req.body.password, 10);
    const user = new User({
        username: req.body.username,
        password: hashedPassword,
        permissions: req.body.permissions
    });
    user.save(err => {
        if (err) return res.status(500).send('Erro ao registrar o usuário.');
        res.status(200).send('Usuário registrado com sucesso!');
    });
});

app.post('/login', (req, res) => {
    User.findOne({ username: req.body.username }, (err, user) => {
        if (err) return res.status(500).send('Erro no servidor.');
        if (!user) return res.status(404).send('Usuário não encontrado.');
        if (!user.isValidPassword(req.body.password)) return res.status(401).send('Senha inválida.');
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).send({ auth: true, token: token });
    });
});

// Middleware de Permissão
function checkPermission(permission) {
    return (req, res, next) => {
        const user = req.user;
        if (user && user.permissions.includes(permission)) {
            next();
        } else {
            res.status(403).send('Acesso negado.');
        }
    };
}

// Conexão com a rede Ethereum
const web3 = new Web3(WEB3_PROVIDER_URL);

// Instância do contrato
const contract = new web3.eth.Contract('<ABI_do_contrato>', CONTRACT_ADDRESS);

// Função para obter o saldo de tokens de um endereço
async function getBalance(address) {
    if (!web3.utils.isAddress(address)) {
        throw new Error('Endereço inválido.');
    }
    const balance = await contract.methods.balanceOf(address).call();
    return balance;
}

// Função para tokenizar ativo
async function tokenizeAsset(amount) {
    if (amount <= 0) {
        throw new Error('A quantidade deve ser um número positivo.');
    }

    const account = web3.eth.accounts.privateKeyToAccount(PRIVATE_KEY);
    web3.eth.accounts.wallet.add(account);
    web3.eth.defaultAccount = account.address;

    const data = contract.methods.mint(account.address, amount).encodeABI();
    const gasEstimate = await web3.eth.estimateGas({
        from: account.address,
        to: CONTRACT_ADDRESS,
        data: data
    });

    const txDetails = {
        from: account.address,
        to: CONTRACT_ADDRESS,
        gas: gasEstimate,
        data: data
    };

    logger.info(`Tokenizando ${amount} tokens...`);
    const receipt = await web3.eth.sendTransaction(txDetails);
    logger.info(`Tokens tokenizados com sucesso! Recibo: ${receipt.transactionHash}`);

    // Salvar detalhes da transação no MongoDB
    const transaction = new Transaction({
        txHash: receipt.transactionHash,
        from: account.address,
        to: CONTRACT_ADDRESS,
        value: amount,
        method: 'tokenizeAsset',
        timestamp: new Date(),
        status: 'pending'
    });
    transaction.save();

    return receipt;
}

// Função para transferir tokens
async function transferTokens(recipientAddress, tokenAmount) {
    if (!web3.utils.isAddress(recipientAddress)) {
        throw new Error('Endereço do destinatário inválido.');
    }

    const account = web3.eth.accounts.privateKeyToAccount(PRIVATE_KEY);
    web3.eth.accounts.wallet.add(account);
    web3.eth.defaultAccount = account.address;

    const data = contract.methods.transfer(recipientAddress, tokenAmount).encodeABI();
    const gasEstimate = await web3.eth.estimateGas({
        from: account.address,
        to: CONTRACT_ADDRESS,
        data: data
    });

    const txDetails = {
        from: account.address,
        to: CONTRACT_ADDRESS,
        gas: gasEstimate,
        data: data
    };

    logger.info(`Transferindo ${tokenAmount} tokens para ${recipientAddress}...`);
    const receipt = await web3.eth.sendTransaction(txDetails);
    logger.info(`Tokens transferidos com sucesso! Recibo: ${receipt.transactionHash}`);

    // Salvar detalhes da transação no MongoDB
    const transaction = new Transaction({
        txHash: receipt.transactionHash,
        from: account.address,
        to: recipientAddress,
        value: tokenAmount,
        method: 'transferTokens',
        timestamp: new Date(),
        status: 'pending'
    });
    transaction.save();

    return receipt;
}

// Função para comprar tokens
async function buyTokens(amount) {
    if (amount <= 0) {
        throw new Error('A quantidade deve ser um número positivo.');
    }

    const account = web3.eth.accounts.privateKeyToAccount(PRIVATE_KEY);
    web3.eth.accounts.wallet.add(account);
    web3.eth.defaultAccount = account.address;

    const data = contract.methods.buyTokens().encodeABI();
    const gasEstimate = await web3.eth.estimateGas({
        from: account.address,
        to: CONTRACT_ADDRESS,
        value: web3.utils.toWei(amount.toString(), 'ether'),
        data: data
    });

    const txDetails = {
        from: account.address,
        to: CONTRACT_ADDRESS,
        gas: gasEstimate,
        value: web3.utils.toWei(amount.toString(), 'ether'),
        data: data
    };

    logger.info(`Comprando tokens com ${amount} Ether...`);
    const receipt = await web3.eth.sendTransaction(txDetails);
    logger.info(`Tokens comprados com sucesso! Recibo: ${receipt.transactionHash}`);

    // Salvar detalhes da transação no MongoDB
    const transaction = new Transaction({
        txHash: receipt.transactionHash,
        from: account.address,
        to: CONTRACT_ADDRESS,
        value: web3.utils.toWei(amount.toString(), 'ether'),
        method: 'buyTokens',
        timestamp: new Date(),
        status: 'pending'
    });
    transaction.save();

    return receipt;
}

// Rotas
/**
 * @swagger
 * /v1/balance/{address}:
 *   get:
 *     tags:
 *       - Balance
 *     description: Retorna o saldo de tokens de um endereço
 *     parameters:
 *       - name: address
 *         in: path
 *         description: Endereço Ethereum
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Saldo em tokens
 */
app.get('/v1/balance/:address', async (req, res, next) => {
    try {
        const balance = await getBalance(req.params.address);
        res.send(`Saldo: ${balance} tokens`);
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /v1/tokenize-asset:
 *   post:
 *     tags:
 *       - Tokenization
 *     description: Tokeniza um ativo
 *     parameters:
 *       - name: amount
 *         in: body
 *         description: Quantidade de tokens
 *         required: true
 *         type: number
 *     responses:
 *       200:
 *         description: Ativo tokenizado com sucesso
 */
app.post('/v1/tokenize-asset', passport.authenticate('jwt', { session: false }), checkPermission('tokenize'), async (req, res, next) => {
    const { amount } = req.body;

    if (!amount) {
        return res.status(400).send('A quantidade de tokens é obrigatória.');
    }

    try {
        await tokenizeAsset(amount);
        res.send('Ativo tokenizado com sucesso!');
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /v1/transfer-tokens:
 *   post:
 *     tags:
 *       - Transfer
 *     description: Transfere tokens
 *     parameters:
 *       - name: recipientAddress
 *         in: body
 *         description: Endereço do destinatário
 *         required: true
 *         type: string
 *       - name: tokenAmount
 *         in: body
 *         description: Quantidade de tokens
 *         required: true
 *         type: number
 *     responses:
 *       200:
 *         description: Tokens transferidos com sucesso
 */
app.post('/v1/transfer-tokens', passport.authenticate('jwt', { session: false }), checkPermission('transfer'), async (req, res, next) => {
    const { recipientAddress, tokenAmount } = req.body;

    if (!recipientAddress || !tokenAmount) {
        return res.status(400).send('Endereço do destinatário e quantidade de tokens são obrigatórios.');
    }

    try {
        await transferTokens(recipientAddress, tokenAmount);
        res.send('Tokens transferidos com sucesso!');
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /v1/buy-tokens:
 *   post:
 *     tags:
 *       - Buy
 *     description: Compra tokens
 *     parameters:
 *       - name: amount
 *         in: body
 *         description: Quantidade de Ether
 *         required: true
 *         type: number
 *     responses:
 *       200:
 *         description: Tokens comprados com sucesso
 */
app.post('/v1/buy-tokens', passport.authenticate('jwt', { session: false }), checkPermission('buy'), async (req, res, next) => {
    const { amount } = req.body;

    if (!amount) {
        return res.status(400).send('A quantidade de Ether é obrigatória.');
    }

    try {
        await buyTokens(amount);
        res.send('Tokens comprados com sucesso!');
    } catch (error) {
        next(error);
    }
});

// Middleware de tratamento de erros
app.use((err, req, res, next) => {
    logger.error(`Erro: ${err.message}`);
    res.status(500).send('Erro interno do servidor.');
});

app.listen(port, () => {
    logger.info(`Servidor rodando na porta ${port}`);
});

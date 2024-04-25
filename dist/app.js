"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const app = (0, express_1.default)();
const PORT = 3000;
const SECRET_KEY = "PZ1W67cMfOfpYW1Ez76LyV0fXEtixSkwocZnCALHDJ0";
const SALT_ROUNDS = 10;
const users = [];
app.use(body_parser_1.default.json());
// -- middleware to authenticate JWT token.
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token)
        return res.sendStatus(401);
    jsonwebtoken_1.default.verify(token, SECRET_KEY, (err, user) => {
        if (err)
            return res.sendStatus(403);
        req.user = user;
        next();
    });
};
// -- signup endpoint
app.post('/signup', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }
    const id = users.length + 1;
    try {
        const hashedPassword = yield bcrypt_1.default.hash(password, SALT_ROUNDS);
        const newUser = { id, username, password: hashedPassword };
        users.push(newUser);
        res.status(201).send('User created successfully');
    }
    catch (error) {
        res.status(500).send('Error creating user');
    }
}));
// -- login endpoint
app.post('/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).send('Invalid username or password');
    }
    try {
        const match = yield bcrypt_1.default.compare(password, user.password);
        if (!match) {
            return res.status(401).send('Invalid username or password');
        }
        const accessToken = jsonwebtoken_1.default.sign({ username: user.username, id: user.id }, SECRET_KEY);
        res.json({ accessToken });
    }
    catch (error) {
        res.status(500).send('Error authenticating user');
    }
}));
// -- secure endpoint, accessible only with a valid jwt token.
app.get('/secure', authenticateToken, (req, res) => {
    const user = req.user;
    res.json({ message: `Welcome, ${user.username}!` });
});
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
exports.default = app;

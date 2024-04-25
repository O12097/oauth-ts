import express from 'express';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();
const PORT = 3000;
const SECRET_KEY = "PZ1W67cMfOfpYW1Ez76LyV0fXEtixSkwocZnCALHDJ0";
const SALT_ROUNDS = 10;

interface User {
    id: number;
    username: string;
    password: string;
}

const users: User[] = [];

app.use(bodyParser.json());

declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
}

// -- middleware to authenticate JWT token.
const authenticateToken = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err: any, user: any) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// -- signup endpoint
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }
    const id = users.length + 1;
    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const newUser: User = { id, username, password: hashedPassword };
        users.push(newUser);
        res.status(201).send('User created successfully');
    } catch (error) {
        res.status(500).send('Error creating user');
    }
});

// -- login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).send('Invalid username or password');
    }
    try {
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).send('Invalid username or password');
        }
        const accessToken = jwt.sign({ username: user.username, id: user.id }, SECRET_KEY);
        res.json({ accessToken });
    } catch (error) {
        res.status(500).send('Error authenticating user');
    }
});

// -- secure endpoint, accessible only with a valid jwt token.
app.get('/secure', authenticateToken, (req, res) => {
    const user = req.user;
    res.json({ message: `Welcome, ${user.username}!` });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

export default app;

const express = require('express');
const jwt = require('jsonwebtoken');
const port = 3000;

const app = express();


const secret_key = "user_management_system";

app.use(express.json());

// In-memory user storage
let users = [];

// Middleware for authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if(token == null){
        return res.status(401).json({error: 'Invalid token provided'});
    }

    jwt.verify(token, secret_key, (err, user) => {
        if(err){
            return res.status(403).json({error: 'Invalid token'});
        }
        req.user = user;
        next();
    });
}


// Register a user (POST /register)
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    if(!username || !password){
        return res.status(400).json({error: 'Username and password are required.'});
    }

    // Check if user already exists
    const existingUser = users.find(user => user.username === username);
    if(existingUser){
        return res.status(400).json({error: 'User already exists.'});
    }

    // Create a new user
    const newUser = { username, password };
    users.push(newUser);
    res.status(201).json({message: 'User registered successfully.'});
});

// Login (POST /login)
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Validata user credentials
    const user = users.find(user => user.username === username && user.password === password);
    if(!user){
        return res.status(401).json({error: 'Invalid credentials'});
    }

    // Generate a token
    const token = jwt.sign({ username: user.username }, secret_key, {expiresIn: '1h'});
    res.json({token});
})


// Get user profile (GET /profile)
app.get('/profile', authenticateToken, (req, res) => {
    const { username } = req.user;

    // Find the user from the username in the token
    const user = users.find(user => user.username === username);
    if(!user){
        return res.status(404).json({error: 'User not found.'});
    }

    res.json({ username: user.username });
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
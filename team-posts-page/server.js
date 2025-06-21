const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const JWT_SECRET = "X9k#mP$2vLqW8xN!rT5uY@hZ3jF6dC4sA7bE2wQ9pL8kJ4mN5xR2tV6yU3iO7gH";

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');

const users = [];
const posts = [];

const authenticateToken = (req, res, next) => {
    let token = null;
    const authHeader = req.headers['authorization'];
    if (authHeader) {
        token = authHeader.split(' ')[1];
    }

    if (!token) {
        const urlParams = new URLSearchParams(req.url.split('?')[1] || '');
        token = urlParams.get('token');
    }

    if (!token) return res.redirect('/login');

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.redirect('/login');
        req.user = user;
        next();
    });
};

app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/register', (req, res) => {
    res.render('register', { message: null });
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (users.find(user => user.username === username)) {
        return res.render('register', { message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login', { message: null });
});

app.post('/login', async (req, res) => {
    console.log('Login request received:', req.body);
    const { username, password } = req.body;
    const user = users.find(user => user.username === username);
    console.log('User found:', user);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        console.log('Invalid username or password');
        return res.render('login', { message: 'Invalid username or password' });
    }

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    console.log('Token generated:', token);
    res.json({ token, redirect: '/posts' });
});

app.get('/posts', authenticateToken, (req, res) => {
    res.render('posts', { posts, username: req.user.username });
});

app.post('/posts', authenticateToken, (req, res) => {
    const { content } = req.body;
    posts.push({ username: req.user.username, content });
    const token = req.headers['authorization']?.split(' ')[1] || new URLSearchParams(req.url.split('?')[1] || '').get('token');
    res.redirect(`/posts?token=${encodeURIComponent(token)}`);
});

app.get('/chat', authenticateToken, (req, res) => {
    res.render('chat', { username: req.user.username });
});

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error'));

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return next(new Error('Authentication error'));
        socket.username = user.username;
        next();
    });
});

io.on('connection', (socket) => {
    socket.on('chat message', (msg) => {
        io.emit('chat message', { username: socket.username, message: msg });
    });

    socket.on('set username', (username) => {
        socket.username = username;
    });
});

const PORT = 8085;
server.listen(PORT);
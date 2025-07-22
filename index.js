const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { OpenAI } = require('openai');

// === CẤU HÌNH ===
const JWT_SECRET = "your_jwt_secret";
const OPENAI_KEY = "your_openai_api_key"; // <-- Nhập API key OpenAI thật của bạn
const openai = new OpenAI({ apiKey: OPENAI_KEY });

const db = new sqlite3.Database('./chatbot.db');
const app = express();
app.use(cors());
app.use(express.json());

// Tạo bảng users nếu chưa có
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE, name TEXT, passwordHash TEXT,
  expirationDate TEXT, role TEXT DEFAULT 'user'
)`);

// Middleware xác thực JWT
function authRequired(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(401);
    req.user = user;
    next();
  });
}

// Đăng ký
app.post('/api/register', async (req, res) => {
  const { email, name, password } = req.body;
  const passwordHash = await bcrypt.hash(password, 10);
  const expirationDate = new Date(Date.now() + 7*24*3600*1000).toISOString(); // 7 ngày
  db.run(
    `INSERT INTO users (email, name, passwordHash, expirationDate) VALUES (?, ?, ?, ?)`,
    [email, name, passwordHash, expirationDate],
    function (err) {
      if (err) return res.status(400).json({ error: "Email đã tồn tại" });
      const user = { id: this.lastID, email, name, expirationDate, role: "user" };
      const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
      res.json({ token, user });
    }
  );
});

// Đăng nhập
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (!user) return res.status(400).json({ error: "Email hoặc mật khẩu sai" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: "Email hoặc mật khẩu sai" });
    if (new Date(user.expirationDate) < new Date()) {
      return res.status(403).json({ error: "Tài khoản hết hạn." });
    }
    const userInfo = { id: user.id, email: user.email, name: user.name, expirationDate: user.expirationDate, role: user.role };
    const token = jwt.sign(userInfo, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: userInfo });
  });
});

// Lấy info user & kiểm tra hạn
app.get('/api/me', authRequired, (req, res) => {
  db.get(`SELECT id, email, name, expirationDate, role FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (!user) return res.sendStatus(404);
    if (new Date(user.expirationDate) < new Date()) {
      return res.status(403).json({ error: "Tài khoản hết hạn." });
    }
    res.json(user);
  });
});

// Chatbot API
app.post('/api/chat', authRequired, async (req, res) => {
  db.get(`SELECT * FROM users WHERE id = ?`, [req.user.id], async (err, user) => {
    if (!user) return res.sendStatus(404);
    if (new Date(user.expirationDate) < new Date()) {
      return res.status(403).json({ error: "Tài khoản hết hạn." });
    }
    try {
      const { messages } = req.body;
      const completion = await openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages,
        max_tokens: 1000,
      });
      res.json({ content: completion.choices[0].message.content });
    } catch (e) {
      res.status(500).json({ error: "OpenAI API error" });
    }
  });
});

// Admin: danh sách user
app.get('/api/admin/users', authRequired, (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);
  db.all(`SELECT id, email, name, expirationDate, role FROM users`, [], (err, rows) => {
    res.json(rows);
  });
});

// Admin: Gia hạn user
app.post('/api/admin/extend', authRequired, (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);
  const { userId, days } = req.body;
  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
    if (!user) return res.sendStatus(404);
    let newExp = new Date(user.expirationDate) > new Date() ? new Date(user.expirationDate) : new Date();
    newExp.setDate(newExp.getDate() + (days || 7));
    db.run(`UPDATE users SET expirationDate = ? WHERE id = ?`, [newExp.toISOString(), userId], function(err){
      if (err) return res.sendStatus(500);
      res.json({ success: true, newExpirationDate: newExp });
    });
  });
});

app.listen(4000, () => console.log('API server on http://localhost:4000'));

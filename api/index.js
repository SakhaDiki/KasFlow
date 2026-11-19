require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

if (!process.env.VERCEL) {
  app.use(express.static(path.join(__dirname, '../public')));
}

const JWT_SECRET = process.env.JWT_SECRET || 'kasflow_secret_key_2026';

let pool;
function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT) || 4000,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME || 'test',
      ssl: process.env.DB_SSL === 'true' ? { minVersion: 'TLSv1.2', rejectUnauthorized: true } : undefined,
      waitForConnections: true,
      connectionLimit: 5,
      queueLimit: 0
    });
  }
  return pool;
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token tidak ditemukan' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token tidak valid atau kedaluwarsa' });
    req.user = user;
    next();
  });
}

// Health check endpoint untuk cek env & koneksi DB di Vercel
app.get('/api/health', async (req, res) => {
  try {
    const db = getPool();
    await db.query('SELECT 1');
    res.json({
      status: 'ok',
      dbConnected: true,
      hasDbHost: Boolean(process.env.DB_HOST)
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message,
      hasDbHost: Boolean(process.env.DB_HOST)
    });
  }
});

// Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Semua kolom wajib diisi' });
  }
  try {
    const db = getPool();
    const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Email sudah terdaftar' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    const user = { id: result.insertId, name, email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email dan kata sandi wajib diisi' });
  }
  try {
    const db = getPool();
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Email atau kata sandi salah' });
    }

    const userRow = rows[0];
    const valid = await bcrypt.compare(password, userRow.password);
    if (!valid) {
      return res.status(401).json({ error: 'Email atau kata sandi salah' });
    }

    const user = { id: userRow.id, name: userRow.name, email: userRow.email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// Get Categories
app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const db = getPool();
    const [rows] = await db.query(
      'SELECT * FROM categories WHERE user_id IS NULL OR user_id = ? ORDER BY type, name',
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create Category
app.post('/api/categories', authenticateToken, async (req, res) => {
  const { name, type } = req.body;
  if (!name || !type) return res.status(400).json({ error: 'Nama dan tipe kategori wajib diisi' });
  try {
    const db = getPool();
    const [result] = await db.query(
      'INSERT INTO categories (user_id, name, type) VALUES (?, ?, ?)',
      [req.user.id, name, type]
    );
    res.status(201).json({ id: result.insertId, name, type });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Transactions
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const db = getPool();
    const [rows] = await db.query(
      `SELECT t.id, t.amount, t.transaction_date, t.note, c.name AS category, c.type
       FROM transactions t
       JOIN categories c ON t.category_id = c.id
       WHERE t.user_id = ?
       ORDER BY t.transaction_date DESC, t.id DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add Transaction
app.post('/api/transactions', authenticateToken, async (req, res) => {
  const { category_id, amount, transaction_date, note } = req.body;
  if (!category_id || !amount || !transaction_date) {
    return res.status(400).json({ error: 'Kategori, nominal, dan tanggal wajib diisi' });
  }
  try {
    const db = getPool();
    const [result] = await db.query(
      'INSERT INTO transactions (user_id, category_id, amount, transaction_date, note) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, category_id, amount, transaction_date, note || '']
    );
    res.status(201).json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete Transaction
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const db = getPool();
    await db.query('DELETE FROM transactions WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server KasFlow aktif di http://localhost:${PORT}`);
  });
}

module.exports = app;
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const JWT_SECRET = process.env.JWT_SECRET || 'kasflow_secret_key_2026';

// Koneksi langsung ke TiDB Cloud / MySQL via .env
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'test',
  ssl: process.env.DB_SSL === 'true' || (process.env.DB_HOST && process.env.DB_HOST !== 'localhost')
    ? { minVersion: 'TLSv1.2', rejectUnauthorized: true }
    : undefined,
  waitForConnections: true,
  connectionLimit: 10
});

// Middleware Verifikasi Login
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Silakan login terlebih dahulu.' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Sesi habis, silakan login ulang.' });
    req.user = decoded;
    next();
  });
}

// 1. Register Akun Baru
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 6) {
      return res.status(400).json({ error: 'Nama, email, dan password minimal 6 karakter wajib diisi.' });
    }
    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) return res.status(409).json({ error: 'Email sudah terdaftar.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      [name, email, passwordHash]
    );
    const user = { id: result.insertId, name, email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Login Akun
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Email tidak ditemukan.' });

    const userRow = rows[0];
    const isMatch = await bcrypt.compare(password, userRow.password_hash);
    if (!isMatch) return res.status(401).json({ error: 'Kata sandi salah.' });

    const user = { id: userRow.id, name: userRow.name, email: userRow.email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Kategori (Bawaan + Kustom User)
app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, name, type FROM categories WHERE user_id IS NULL OR user_id = ? ORDER BY type, name',
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/categories', authenticateToken, async (req, res) => {
  try {
    const { name, type } = req.body;
    if (!name || !['INCOME', 'EXPENSE'].includes(type)) {
      return res.status(400).json({ error: 'Nama dan jenis kategori tidak valid.' });
    }
    const [result] = await pool.query(
      'INSERT INTO categories (user_id, name, type) VALUES (?, ?, ?)',
      [req.user.id, name.trim(), type]
    );
    res.status(201).json({ id: result.insertId, name: name.trim(), type });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Transaksi per User
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
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

app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { category_id, amount, transaction_date, note } = req.body;
    if (!category_id || !amount || !transaction_date) {
      return res.status(400).json({ error: 'Kategori, nominal, dan tanggal wajib diisi.' });
    }
    const [result] = await pool.query(
      'INSERT INTO transactions (user_id, category_id, amount, transaction_date, note) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, category_id, amount, transaction_date, note || null]
    );
    res.status(201).json({ id: result.insertId, message: 'Transaksi tersimpan' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM transactions WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ message: 'Transaksi dihapus' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server KasFlow aktif di http://localhost:${PORT}`));
}

module.exports = app;
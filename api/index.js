const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'kasflow_secret_key_2026';

app.use(cors());
app.use(express.json());

let pool;
function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT) || 4000,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME || 'test',
      ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
      },
      waitForConnections: true,
      connectionLimit: 5,
      queueLimit: 0
    });
  }
  return pool;
}

// Middleware verifikasi JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Token tidak ditemukan. Silakan login kembali.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Sesi berakhir. Silakan login kembali.' });
    }
    req.user = user;
    next();
  });
}

// Health Check Database
app.get('/api/health', async (req, res) => {
  try {
    const db = getPool();
    await db.query('SELECT 1');
    res.json({ status: 'ok', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// Register (Hanya 1 endpoint bersih)
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Nama, email, dan kata sandi wajib diisi' });
  }

  try {
    const db = getPool();
    const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Email sudah terdaftar' });
    }

    const hashedPassword = await bcrypt.hash(String(password), 10);

    // Cek nama kolom password di tabel users (password_hash atau password)
    const [cols] = await db.query("SHOW COLUMNS FROM users LIKE 'password_hash'");
    const passCol = cols.length > 0 ? 'password_hash' : 'password';

    const [result] = await db.query(
      `INSERT INTO users (name, email, ${passCol}) VALUES (?, ?, ?)`,
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

// Login (Hanya 1 endpoint bersih)
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
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
    const storedHash = userRow.password_hash || userRow.password;
    if (!storedHash) {
      return res.status(500).json({
        error: `Hash password kosong di database. Kolom tersedia: ${Object.keys(userRow).join(', ')}`
      });
    }

    const valid = await bcrypt.compare(String(password), String(storedHash));
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
    const [rows] = await db.query('SELECT * FROM categories ORDER BY id ASC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Gagal memuat kategori: ' + err.message });
  }
});

// Add Category
app.post('/api/categories', authenticateToken, async (req, res) => {
  const { name, type } = req.body || {};
  if (!name || !type) {
    return res.status(400).json({ error: 'Nama dan tipe kategori wajib diisi' });
  }
  try {
    const db = getPool();
    const [result] = await db.query(
      'INSERT INTO categories (name, type) VALUES (?, ?)',
      [name, type]
    );
    res.status(201).json({ id: result.insertId, name, type });
  } catch (err) {
    res.status(500).json({ error: 'Gagal menambah kategori: ' + err.message });
  }
});

// Get Transactions
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const db = getPool();
    const [rows] = await db.query(
      `SELECT t.*, c.name AS category_name, c.type AS category_type
       FROM transactions t
       LEFT JOIN categories c ON t.category_id = c.id
       WHERE t.user_id = ?
       ORDER BY t.date DESC, t.id DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Gagal memuat transaksi: ' + err.message });
  }
});

// Add Transaction
app.post('/api/transactions', authenticateToken, async (req, res) => {
  const { category_id, amount, type, description, date } = req.body || {};
  if (!category_id || !amount || !type || !date) {
    return res.status(400).json({ error: 'Kategori, jumlah, tipe, dan tanggal wajib diisi' });
  }
  try {
    const db = getPool();
    const [result] = await db.query(
      'INSERT INTO transactions (user_id, category_id, amount, type, description, date) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, category_id, amount, type, description || '', date]
    );
    res.status(201).json({
      id: result.insertId,
      user_id: req.user.id,
      category_id,
      amount,
      type,
      description: description || '',
      date
    });
  } catch (err) {
    res.status(500).json({ error: 'Gagal menyimpan transaksi: ' + err.message });
  }
});

// Delete Transaction
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const db = getPool();
    const [result] = await db.query(
      'DELETE FROM transactions WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Transaksi tidak ditemukan' });
    }
    res.json({ message: 'Transaksi berhasil dihapus' });
  } catch (err) {
    res.status(500).json({ error: 'Gagal menghapus transaksi: ' + err.message });
  }
});

// Jalankan server lokal jika tidak di Vercel
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
  });
}

module.exports = app;
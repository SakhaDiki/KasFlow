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
      ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true },
      waitForConnections: true,
      connectionLimit: 5,
      queueLimit: 0
    });
  }
  return pool;
}

let schemaReady = false;
async function ensureUserSchema(db) {
  if (schemaReady) return;
  try {
    const [cols] = await db.query("SHOW COLUMNS FROM users LIKE 'username'");
    if (cols.length === 0) {
      await db.query("ALTER TABLE users ADD COLUMN username VARCHAR(100) NULL AFTER id");
      await db.query("ALTER TABLE users MODIFY COLUMN email VARCHAR(255) NULL");
      await db.query("UPDATE users SET username = 'sakha' WHERE email = 'cendikiasakhaasshidiqie@gmail.com'");
      await db.query("UPDATE users SET username = 'sakhadiki' WHERE email = 'sakhadiki8@gmail.com'");
      await db.query("UPDATE users SET username = CONCAT('user_', id) WHERE username IS NULL OR username = ''");
      await db.query("ALTER TABLE users ADD UNIQUE INDEX idx_users_username (username)");
    }
    schemaReady = true;
  } catch (e) {
    console.error('Schema check warning:', e.message);
  }
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token tidak ditemukan. Silakan login kembali.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Sesi berakhir. Silakan login kembali.' });
    req.user = user;
    next();
  });
}

// Health Check
app.get('/api/health', async (req, res) => {
  try {
    const db = getPool();
    await ensureUserSchema(db);
    await db.query('SELECT 1');
    res.json({ status: 'ok', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// Register (Username + Password)
app.post('/api/auth/register', async (req, res) => {
  const { name, username, password } = req.body || {};
  const cleanUser = String(username || '').trim().toLowerCase();
  if (!cleanUser || !password) {
    return res.status(400).json({ error: 'Username dan kata sandi wajib diisi' });
  }

  try {
    const db = getPool();
    await ensureUserSchema(db);
    const [existing] = await db.query('SELECT id FROM users WHERE username = ?', [cleanUser]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Username sudah digunakan' });
    }

    const hashedPassword = await bcrypt.hash(String(password), 10);
    const [cols] = await db.query("SHOW COLUMNS FROM users LIKE 'password_hash'");
    const passCol = cols.length > 0 ? 'password_hash' : 'password';

    const [result] = await db.query(
      `INSERT INTO users (name, username, ${passCol}) VALUES (?, ?, ?)`,
      [name || cleanUser, cleanUser, hashedPassword]
    );

    const user = { id: result.insertId, name: name || cleanUser, username: cleanUser };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user });
  } catch (err) {
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// Login (Username + Password)
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  const cleanUser = String(username || '').trim().toLowerCase();
  if (!cleanUser || !password) {
    return res.status(400).json({ error: 'Username dan kata sandi wajib diisi' });
  }

  try {
    const db = getPool();
    await ensureUserSchema(db);
    const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [cleanUser]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Username atau kata sandi salah' });
    }

    const userRow = rows[0];
    const storedHash = userRow.password_hash || userRow.password;
    const valid = await bcrypt.compare(String(password), String(storedHash));
    if (!valid) {
      return res.status(401).json({ error: 'Username atau kata sandi salah' });
    }

    const user = { id: userRow.id, name: userRow.name, username: userRow.username };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// Update Account (Ganti Username & Kata Sandi Sekaligus)
app.post('/api/auth/update-account', authenticateToken, async (req, res) => {
  const { currentPassword, newUsername, newPassword } = req.body || {};
  if (!currentPassword) {
    return res.status(400).json({ error: 'Kata sandi saat ini wajib diisi untuk verifikasi' });
  }

  const cleanUsername = newUsername ? String(newUsername).trim().toLowerCase() : '';
  const hasNewPassword = Boolean(newPassword && String(newPassword).length > 0);

  if (!cleanUsername && !hasNewPassword) {
    return res.status(400).json({ error: 'Isi username baru atau kata sandi baru yang ingin diubah' });
  }
  if (hasNewPassword && String(newPassword).length < 6) {
    return res.status(400).json({ error: 'Kata sandi baru minimal 6 karakter' });
  }

  try {
    const db = getPool();
    await ensureUserSchema(db);
    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Pengguna tidak ditemukan' });

    const userRow = rows[0];
    const storedHash = userRow.password_hash || userRow.password;
    const isMatch = await bcrypt.compare(String(currentPassword), String(storedHash));
    if (!isMatch) return res.status(401).json({ error: 'Kata sandi saat ini tidak sesuai' });

    let finalUsername = userRow.username;
    if (cleanUsername && cleanUsername !== userRow.username) {
      const [dup] = await db.query('SELECT id FROM users WHERE username = ? AND id != ?', [cleanUsername, req.user.id]);
      if (dup.length > 0) return res.status(409).json({ error: 'Username sudah digunakan akun lain' });
      finalUsername = cleanUsername;
    }

    const updates = [];
    const params = [];

    if (finalUsername !== userRow.username) {
      updates.push('username = ?');
      params.push(finalUsername);
    }
    if (hasNewPassword) {
      const newHash = await bcrypt.hash(String(newPassword), 10);
      const col = userRow.password_hash !== undefined ? 'password_hash' : 'password';
      updates.push(`${col} = ?`);
      params.push(newHash);
    }
    if (updates.length === 0) {
      return res.status(400).json({ error: 'Tidak ada perubahan data yang dimasukkan' });
    }

    params.push(req.user.id);
    await db.query(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);

    const updatedUser = { id: userRow.id, name: userRow.name, username: finalUsername };
    const newToken = jwt.sign(updatedUser, JWT_SECRET, { expiresIn: '7d' });

    res.json({ message: 'Akun berhasil diperbarui', token: newToken, user: updatedUser });
    } catch (err) {
    res.status(500).json({ error: 'Gagal memperbarui akun: ' + err.message });
  }
});

app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const db = getPool();
    const [rows] = await db.query('SELECT * FROM categories WHERE user_id IS NULL OR user_id = ? ORDER BY id ASC', [req.user.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/categories', authenticateToken, async (req, res) => {
  const { name, type } = req.body || {};
  if (!name || !type) return res.status(400).json({ error: 'Nama dan tipe kategori wajib diisi' });
  try {
    const db = getPool();
    const [result] = await db.query('INSERT INTO categories (user_id, name, type) VALUES (?, ?, ?)', [req.user.id, name, type]);
    res.status(201).json({ id: result.insertId, user_id: req.user.id, name, type });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const db = getPool();
    const [rows] = await db.query(
      `SELECT t.id, t.user_id, t.category_id, t.amount, t.transaction_date, t.transaction_date AS date,
              t.note, t.note AS description, c.name AS category_name, c.type AS type, c.type AS category_type
       FROM transactions t LEFT JOIN categories c ON t.category_id = c.id
       WHERE t.user_id = ? ORDER BY t.transaction_date DESC, t.id DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
  const { category_id, amount, transaction_date, date, note, description } = req.body || {};
  const finalDate = transaction_date || date;
  const finalNote = note !== undefined ? note : (description || '');
  if (!category_id || !amount || !finalDate) return res.status(400).json({ error: 'Kategori, jumlah, dan tanggal wajib diisi' });
  try {
    const db = getPool();
    const [result] = await db.query(
      'INSERT INTO transactions (user_id, category_id, amount, transaction_date, note) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, category_id, amount, finalDate, finalNote]
    );
    res.status(201).json({ id: result.insertId, user_id: req.user.id, category_id, amount, transaction_date: finalDate, date: finalDate, note: finalNote, description: finalNote });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const db = getPool();
    const [result] = await db.query('DELETE FROM transactions WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Transaksi tidak ditemukan' });
    res.json({ message: 'Transaksi berhasil dihapus' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server berjalan di http://localhost:${PORT}`));
}

module.exports = app;
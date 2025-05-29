// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Middleware to check if user is admin
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Initialize database tables
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        role VARCHAR(50) DEFAULT 'contractor',
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        company_name VARCHAR(255),
        vat_number VARCHAR(50)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS invitations (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        token VARCHAR(255) UNIQUE NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        invited_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        used_at TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS policies (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        policy_number VARCHAR(100) UNIQUE NOT NULL,
        numero_polizza VARCHAR(50),
        
        -- Contraente fields
        contraente_nome VARCHAR(255),
        contraente_cf VARCHAR(50),
        contraente_via VARCHAR(255),
        contraente_citta VARCHAR(100),
        contraente_cap VARCHAR(10),
        contraente_provincia VARCHAR(5),
        contraente_pec VARCHAR(255),
        
        -- Beneficiario fields
        beneficiario_nome VARCHAR(255),
        beneficiario_cf VARCHAR(50),
        beneficiario_via VARCHAR(255),
        beneficiario_citta VARCHAR(100),
        beneficiario_cap VARCHAR(10),
        beneficiario_provincia VARCHAR(5),
        beneficiario_pec VARCHAR(255),
        
        -- Contract details
        oggetto TEXT,
        luogo_esecuzione VARCHAR(255),
        costo_aggiudicazione DECIMAL(12, 2),
        tipologia VARCHAR(100),
        
        -- Financial fields
        importo DECIMAL(12, 2),
        decorrenza DATE,
        scadenza DATE,
        tasso_lordo DECIMAL(5, 2),
        diritti DECIMAL(10, 2),
        premio_firma DECIMAL(10, 2),
        
        -- Legacy fields for compatibility
        intermediario VARCHAR(255),
        firma_digitale BOOLEAN DEFAULT false,
        
        status VARCHAR(50) DEFAULT 'draft',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        pdf_url TEXT
      )
    `);

    // Create default admin user if not exists
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@broker.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    
    const existingAdmin = await pool.query('SELECT id FROM users WHERE email = $1', [adminEmail]);
    
    if (existingAdmin.rows.length === 0) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      await pool.query(
        'INSERT INTO users (email, password_hash, role, status) VALUES ($1, $2, $3, $4)',
        [adminEmail, hashedPassword, 'admin', 'active']
      );
      console.log(`Admin user created: ${adminEmail}`);
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Routes

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if user needs to set password (first login)
    if (!user.password_hash && user.status === 'pending') {
      return res.json({ 
        requiresPasswordSetup: true, 
        email: user.email,
        userId: user.id 
      });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.status !== 'active') {
      return res.status(401).json({ error: 'Account not active' });
    }

    // Update last login
    await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        company_name: user.company_name
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Set password for first login
app.post('/api/auth/set-password', async (req, res) => {
  try {
    const { email, password, invitationToken } = req.body;

    // Verify invitation token if provided
    if (invitationToken) {
      const inviteResult = await pool.query(
        'SELECT * FROM invitations WHERE token = $1 AND status = $2',
        [invitationToken, 'pending']
      );

      if (inviteResult.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid or expired invitation' });
      }

      // Mark invitation as used
      await pool.query(
        'UPDATE invitations SET status = $1, used_at = CURRENT_TIMESTAMP WHERE token = $2',
        ['used', invitationToken]
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    await pool.query(
      'UPDATE users SET password_hash = $1, status = $2 WHERE email = $3',
      [hashedPassword, 'active', email]
    );

    res.json({ message: 'Password set successfully' });
  } catch (error) {
    console.error('Set password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, role, company_name, vat_number FROM users WHERE id = $1',
      [req.user.id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Get all users
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, role, status, company_name, created_at, last_login FROM users ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Invite contractor
app.post('/api/admin/invite', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { email, companyName } = req.body;
    
    // Check if user already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Create user account
    const userResult = await pool.query(
      'INSERT INTO users (email, role, status, company_name) VALUES ($1, $2, $3, $4) RETURNING id',
      [email, 'contractor', 'pending', companyName]
    );

    // Generate invitation token
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
    
    await pool.query(
      'INSERT INTO invitations (email, token, invited_by) VALUES ($1, $2, $3)',
      [email, token, req.user.id]
    );

    // In production, send email here
    const inviteLink = `${process.env.FRONTEND_URL || (process.env.NODE_ENV === 'production' ? 'https://broker-plus.onrender.com' : 'http://localhost:3001')}/set-password.html?token=${token}&email=${encodeURIComponent(email)}`;
    
    res.json({ 
      message: 'Invitation sent successfully',
      inviteLink, // Now always included so you can share it manually
      userId: userResult.rows[0].id
    });
  } catch (error) {
    console.error('Invite error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Delete user
app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Don't allow deleting admin users
    const userResult = await pool.query('SELECT role FROM users WHERE id = $1', [id]);
    if (userResult.rows[0]?.role === 'admin') {
      return res.status(400).json({ error: 'Cannot delete admin users' });
    }

    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get policies (admin sees all, contractors see their own)
app.get('/api/policies', authenticateToken, async (req, res) => {
  try {
    let query;
    let params = [];

    if (req.user.role === 'admin') {
      query = `
        SELECT p.*, u.email as user_email, u.company_name 
        FROM policies p 
        JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_at DESC
      `;
    } else {
      query = `
        SELECT * FROM policies 
        WHERE user_id = $1 
        ORDER BY created_at DESC
      `;
      params = [req.user.id];
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Get policies error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create policy
app.post('/api/policies', authenticateToken, async (req, res) => {
  try {
    const {
      contraente_cf,
      intermediario,
      oggetto,
      tipologia,
      firma_digitale,
      importo,
      decorrenza,
      scadenza,
      tasso_lordo,
      diritti,
      premio_firma
    } = req.body;

    // Generate unique policy number
    const policyNumber = `POL-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    const result = await pool.query(
      `INSERT INTO policies (
        user_id, policy_number, contraente_cf, intermediario, oggetto, 
        tipologia, firma_digitale, importo, decorrenza, scadenza, 
        tasso_lordo, diritti, premio_firma
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
      RETURNING *`,
      [
        req.user.id, policyNumber, contraente_cf, intermediario, oggetto,
        tipologia, firma_digitale, importo, decorrenza, scadenza,
        tasso_lordo, diritti, premio_firma
      ]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Create policy error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update policy
app.put('/api/policies/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    // Check ownership
    const ownerCheck = await pool.query(
      'SELECT user_id FROM policies WHERE id = $1',
      [id]
    );

    if (ownerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Policy not found' });
    }

    if (req.user.role !== 'admin' && ownerCheck.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Build update query dynamically
    const fields = Object.keys(updates);
    const values = Object.values(updates);
    const setClause = fields.map((field, index) => `${field} = $${index + 2}`).join(', ');

    const query = `
      UPDATE policies 
      SET ${setClause}, updated_at = CURRENT_TIMESTAMP 
      WHERE id = $1 
      RETURNING *
    `;

    const result = await pool.query(query, [id, ...values]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update policy error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete policy
app.delete('/api/policies/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Check ownership
    const ownerCheck = await pool.query(
      'SELECT user_id FROM policies WHERE id = $1',
      [id]
    );

    if (ownerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Policy not found' });
    }

    if (req.user.role !== 'admin' && ownerCheck.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await pool.query('DELETE FROM policies WHERE id = $1', [id]);
    res.json({ message: 'Policy deleted successfully' });
  } catch (error) {
    console.error('Delete policy error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Temporary migration endpoint - REMOVE AFTER RUNNING
app.get('/api/migrate-db', authenticateToken, isAdmin, async (req, res) => {
  try {
    // Add new columns if they don't exist
    const alterQueries = [
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS numero_polizza VARCHAR(50)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS contraente_nome VARCHAR(255)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS contraente_via VARCHAR(255)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS contraente_citta VARCHAR(100)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS contraente_cap VARCHAR(10)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS contraente_provincia VARCHAR(5)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS contraente_pec VARCHAR(255)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS beneficiario_nome VARCHAR(255)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS beneficiario_cf VARCHAR(50)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS beneficiario_via VARCHAR(255)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS beneficiario_citta VARCHAR(100)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS beneficiario_cap VARCHAR(10)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS beneficiario_provincia VARCHAR(5)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS beneficiario_pec VARCHAR(255)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS luogo_esecuzione VARCHAR(255)',
      'ALTER TABLE policies ADD COLUMN IF NOT EXISTS costo_aggiudicazione DECIMAL(12, 2)'
    ];

    for (const query of alterQueries) {
      await pool.query(query);
    }

    res.json({ message: 'Database migrated successfully' });
  } catch (error) {
    console.error('Migration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Start server
initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Admin login: ${process.env.ADMIN_EMAIL || 'admin@broker.com'}`);
  });
});
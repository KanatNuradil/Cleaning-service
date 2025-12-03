const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'mysupersecretkey123';
const ORDER_STATUSES = [
  'Paid',
  'Accept order',
  'Going to home',
  'Arrived to home',
  'Start cleaning',
  'Finish cleaning'
];
const INITIAL_ORDER_STATUS = ORDER_STATUSES[0];
const LEGACY_STATUS_MAP = {
  'Order accepted': 'Accept order',
  'Going to your home': 'Going to home',
  'Arrived to your home': 'Arrived to home',
  'Starting the cleaning': 'Start cleaning',
  'Finished': 'Finish cleaning'
};

const CITY_OPTIONS = [
  'Алматы',
  'Астана',
  'Шымкент',
  'Актобе',
  'Караганда',
  'Тараз',
  'Усть-Каменогорск',
  'Павлодар',
  'Атырау',
  'Семей',
  'Туркестан',
  'Костанай',
  'Петропавл',
  'Темиртау',
  'Кокшетау',
  'Актау',
  'Уральск',
  'Жетисай',
  'Кызылорда'
];

// Middleware
app.use(helmet());
app.use(cors({
  origin: true, // Allow all origins for development
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.static('.'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Database setup
const db = new sqlite3.Database('./database.sqlite');

// Initialize database tables
db.serialize(() => {
  // Customers / users table with role
  db.run(`CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT NOT NULL,
    city TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer', -- customer | admin | cleaner
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Backwards‑compatible migration: ensure role & cleaner fields exist
  db.run(`ALTER TABLE customers ADD COLUMN role TEXT NOT NULL DEFAULT 'customer'`, (err) => {
    if (err && !/duplicate column name/i.test(err.message)) {
      console.error('Migration (customers.role) error:', err.message);
    }
  });
  db.run(`ALTER TABLE customers ADD COLUMN city TEXT`, (err) => {
    if (err && !/duplicate column name/i.test(err.message)) {
      console.error('Migration (customers.city) error:', err.message);
    }
  });

  // Orders table
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    property_type TEXT NOT NULL,
    rooms INTEGER NOT NULL,
    bathrooms INTEGER NOT NULL,
    cleaning_type TEXT NOT NULL,
    base_price REAL NOT NULL,
    addons TEXT NOT NULL,
    total_price REAL NOT NULL,
    schedule_date TEXT NOT NULL,
    schedule_time TEXT NOT NULL,
    address_street TEXT NOT NULL,
    address_house TEXT NOT NULL,
    address_apartment TEXT,
    address_floor TEXT,
    address_comment TEXT,
    status TEXT DEFAULT '${INITIAL_ORDER_STATUS}',
    cleaner_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers (id),
    FOREIGN KEY (cleaner_id) REFERENCES customers (id)
  )`);

  // Backwards‑compatible migration for older orders table
  db.run(`ALTER TABLE orders ADD COLUMN cleaner_id INTEGER`, (err) => {
    if (err && !/duplicate column name/i.test(err.message)) {
      console.error('Migration (orders.cleaner_id) error:', err.message);
    }
  });
  db.run(`ALTER TABLE orders ADD COLUMN status TEXT DEFAULT '${INITIAL_ORDER_STATUS}'`, (err) => {
    if (err && !/duplicate column name/i.test(err.message)) {
      console.error('Migration (orders.status) error:', err.message);
    }
  });
  db.run(
    'UPDATE orders SET status = ? WHERE status IS NULL OR TRIM(status) = ?',
    [INITIAL_ORDER_STATUS, ''],
    (err) => {
      if (err) {
        console.error('Backfill order status error:', err.message);
      }
    }
  );
  Object.entries(LEGACY_STATUS_MAP).forEach(([oldValue, newValue]) => {
    db.run('UPDATE orders SET status = ? WHERE status = ?', [newValue, oldValue], (err) => {
      if (err) {
        console.error(`Failed to migrate status "${oldValue}" -> "${newValue}":`, err.message);
      }
    });
  });

  // Cleaner work schedules
  db.run(`CREATE TABLE IF NOT EXISTS cleaner_schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cleaner_id INTEGER NOT NULL,
    work_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cleaner_id) REFERENCES customers (id)
  )`);

  // Password reset tokens
  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers (id)
  )`);

  // Seed or refresh a default admin user so credentials are always known
  const adminEmail = process.env.ADMIN_EMAIL || 'Admin@localhost.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'CleanAdmin#2025';

  db.get('SELECT id FROM customers WHERE email = ?', [adminEmail], (err, row) => {
    if (err) {
      console.error('Error checking for admin user:', err.message);
      return;
    }
    bcrypt.hash(adminPassword, 10, (hashErr, hash) => {
      if (hashErr) {
        console.error('Error hashing admin password:', hashErr.message);
        return;
      }
      if (row) {
        db.run(
          'UPDATE customers SET role = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
          ['admin', hash, row.id],
          function (updateErr) {
            if (updateErr) {
              console.error('Failed to refresh admin user:', updateErr.message);
            } else {
              console.log(`Admin user refreshed with email ${adminEmail}`);
            }
          }
        );
      } else {
        db.run(
          'INSERT INTO customers (first_name, last_name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)',
          ['Admin', 'User', adminEmail, 'N/A', hash, 'admin'],
          function (insertErr) {
            if (insertErr) {
              console.error('Failed to create admin user:', insertErr.message);
            } else {
              console.log(`Admin user created with email ${adminEmail} (id=${this.lastID})`);
            }
          }
        );
      }
    });
  });

  console.log('Database tables initialized');
});

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Role-based authorization middleware
const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Insufficient permissions' });
    }
    next();
  };
};

// Validation schemas
const registerSchema = Joi.object({
  firstName: Joi.string().min(2).max(50).required(),
  lastName: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().required(),
  phone: Joi.string().pattern(/^\+?[\d\s\-\(\)]+$/).required(),
  password: Joi.string().min(8).required()
});

const createCleanerSchema = Joi.object({
  firstName: Joi.string().min(2).max(50).required(),
  lastName: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().required(),
  phone: Joi.string().pattern(/^\+?[\d\s\-\(\)]+$/).required(),
  password: Joi.string().min(8).required()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const orderSchema = Joi.object({
  property_type: Joi.string().valid('apartment', 'house').required(),
  rooms: Joi.number().integer().min(1).max(10).required(),
  bathrooms: Joi.number().integer().min(1).max(5).required(),
  cleaning_type: Joi.string().valid('standard', 'deep', 'postreno').required(),
  base_price: Joi.number().positive().required(),
  addons: Joi.array().items(Joi.object({
    key: Joi.string().required(),
    label: Joi.string().required(),
    qty: Joi.number().integer().min(0).required(),
    price: Joi.number().min(0).required()
  })).required(),
  total_price: Joi.number().positive().required(),
  schedule_date: Joi.string().required(),
  schedule_time: Joi.string().required(),
  address_street: Joi.string().min(1).required(),
  address_house: Joi.string().min(1).required(),
  address_apartment: Joi.string().allow(''),
  address_floor: Joi.string().allow(''),
  address_comment: Joi.string().allow('')
});

const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required()
});

const resetPasswordSchema = Joi.object({
  token: Joi.string().length(64).required(),
  password: Joi.string().min(8).required()
});

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { firstName, lastName, email, phone, password } = value;

    // Check if user already exists
    db.get('SELECT id FROM customers WHERE email = ?', [email], (err, row) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      if (row) {
        return res.status(400).json({ message: 'Email already registered' });
      }

      // Hash password and create user
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          return res.status(500).json({ message: 'Password hashing error' });
        }

        db.run(
          'INSERT INTO customers (first_name, last_name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)',
          [firstName, lastName, email, phone, hash, 'customer'],
          function(err) {
            if (err) {
              return res.status(500).json({ message: 'Failed to create user' });
            }

            const tokenPayload = { id: this.lastID, email, role: 'customer' };
            const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });

            res.status(201).json({
              message: 'User created successfully',
              token,
              user: {
                id: this.lastID,
                firstName,
                lastName,
                email,
                phone,
                role: 'customer',
                city: null
              }
            });
          }
        );
      });
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { email, password } = value;

    db.get('SELECT * FROM customers WHERE email = ?', [email], (err, user) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      bcrypt.compare(password, user.password_hash, (err, isMatch) => {
        if (err) {
          return res.status(500).json({ message: 'Password verification error' });
        }
        if (!isMatch) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }

        const tokenPayload = { id: user.id, email: user.email, role: user.role || 'customer' };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });

        res.json({
          message: 'Login successful',
          token,
          user: {
            id: user.id,
            firstName: user.first_name,
            lastName: user.last_name,
            email: user.email,
            phone: user.phone,
            role: user.role || 'customer',
            city: user.city || null
          }
        });
      });
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Password recovery - request reset
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { error, value } = forgotPasswordSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { email } = value;
    db.get('SELECT id FROM customers WHERE email = ?', [email], (err, user) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }

      // Always respond OK to prevent email enumeration
      const respondOk = (tokenForDemo) => {
        return res.json({ message: 'If the email exists, a reset link has been created.', demoToken: tokenForDemo });
      };

      if (!user) {
        return respondOk(null);
      }

      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 1000 * 60 * 30).toISOString(); // 30 minutes

      db.run(
        'INSERT INTO password_resets (customer_id, token, expires_at) VALUES (?, ?, ?)',
        [user.id, token, expiresAt],
        function(insertErr) {
          if (insertErr) {
            return res.status(500).json({ message: 'Failed to create reset request' });
          }
          // In production, send email with the token link. For demo, return token.
          respondOk(token);
        }
      );
    });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Password recovery - reset
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { error, value } = resetPasswordSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { token, password } = value;
    db.get(
      `SELECT pr.id as reset_id, pr.customer_id, pr.expires_at, pr.used
       FROM password_resets pr WHERE pr.token = ?`,
      [token],
      (err, row) => {
        if (err) {
          return res.status(500).json({ message: 'Database error' });
        }
        if (!row) {
          return res.status(400).json({ message: 'Invalid token' });
        }
        if (row.used) {
          return res.status(400).json({ message: 'Token already used' });
        }
        if (new Date(row.expires_at).getTime() < Date.now()) {
          return res.status(400).json({ message: 'Token expired' });
        }

        bcrypt.hash(password, 10, (hashErr, hash) => {
          if (hashErr) {
            return res.status(500).json({ message: 'Password hashing error' });
          }

          db.run('UPDATE customers SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [hash, row.customer_id], function(updateErr) {
            if (updateErr) {
              return res.status(500).json({ message: 'Failed to update password' });
            }

            db.run('UPDATE password_resets SET used = 1 WHERE id = ?', [row.reset_id], function(markErr) {
              if (markErr) {
                return res.status(500).json({ message: 'Failed to finalize reset' });
              }
              res.json({ message: 'Password updated successfully' });
            });
          });
        });
      }
    );
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Order routes
app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { error, value } = orderSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const {
      property_type, rooms, bathrooms, cleaning_type, base_price, addons,
      total_price, schedule_date, schedule_time, address_street, address_house,
      address_apartment, address_floor, address_comment
    } = value;

    const customerId = req.user?.id;
    if (!customerId) {
      return res.status(401).json({ message: 'Authenticated user required' });
    }

    db.run(
      `INSERT INTO orders (
        customer_id, property_type, rooms, bathrooms, cleaning_type, base_price,
        addons, total_price, schedule_date, schedule_time, address_street,
        address_house, address_apartment, address_floor, address_comment, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
          customerId, property_type, rooms, bathrooms, cleaning_type, base_price,
        JSON.stringify(addons), total_price, schedule_date, schedule_time,
        address_street, address_house, address_apartment, address_floor, address_comment, INITIAL_ORDER_STATUS
      ],
      function(err) {
        if (err) {
          console.error('Order creation error:', err);
          return res.status(500).json({ message: 'Failed to create order' });
        }

        res.status(201).json({
          message: 'Order created successfully',
          orderId: this.lastID
        });
      }
    );
  } catch (error) {
    console.error('Order error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin: list all orders with customer & cleaner info
app.get('/api/admin/orders', authenticateToken, authorizeRoles('admin'), (req, res) => {
  const sql = `
    SELECT
      o.*,
      c.first_name AS customer_first_name,
      c.last_name AS customer_last_name,
      cl.first_name AS cleaner_first_name,
      cl.last_name AS cleaner_last_name
    FROM orders o
    JOIN customers c ON o.customer_id = c.id
    LEFT JOIN customers cl ON o.cleaner_id = cl.id
    ORDER BY o.created_at DESC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Admin orders error:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    const orders = rows.map(row => ({
      id: row.id,
      customer: {
        id: row.customer_id,
        firstName: row.customer_first_name,
        lastName: row.customer_last_name
      },
      cleaner: row.cleaner_id
        ? { id: row.cleaner_id, firstName: row.cleaner_first_name, lastName: row.cleaner_last_name }
        : null,
      property_type: row.property_type,
      rooms: row.rooms,
      bathrooms: row.bathrooms,
      cleaning_type: row.cleaning_type,
      base_price: row.base_price,
      addons: JSON.parse(row.addons),
      total_price: row.total_price,
      schedule_date: row.schedule_date,
      schedule_time: row.schedule_time,
      address: {
        street: row.address_street,
        house: row.address_house,
        apartment: row.address_apartment,
        floor: row.address_floor,
        comment: row.address_comment
      },
      status: row.status,
      created_at: row.created_at,
      updated_at: row.updated_at
    }));
    res.json({ orders, statuses: ORDER_STATUSES });
  });
});

// Admin: list all cleaners
app.get('/api/admin/cleaners', authenticateToken, authorizeRoles('admin'), (req, res) => {
  db.all(
    'SELECT id, first_name, last_name, email, phone FROM customers WHERE role = ? ORDER BY first_name ASC',
    ['cleaner'],
    (err, rows) => {
      if (err) {
        console.error('Admin cleaners error:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({
        cleaners: rows.map(r => ({
          id: r.id,
          firstName: r.first_name,
          lastName: r.last_name,
          email: r.email,
          phone: r.phone
        }))
      });
    }
  );
});

// Admin: create a cleaner account
app.post('/api/admin/cleaners', authenticateToken, authorizeRoles('admin'), (req, res) => {
  const { error, value } = createCleanerSchema.validate(req.body || {});
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }
  const { firstName, lastName, email, phone, password } = value;

  db.get('SELECT id FROM customers WHERE email = ?', [email], (findErr, row) => {
    if (findErr) {
      return res.status(500).json({ message: 'Database error' });
    }
    if (row) {
      return res.status(400).json({ message: 'Email already registered' });
    }
    bcrypt.hash(password, 10, (hashErr, hash) => {
      if (hashErr) {
        return res.status(500).json({ message: 'Password hashing error' });
      }
      db.run(
        'INSERT INTO customers (first_name, last_name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)',
        [firstName, lastName, email, phone, hash, 'cleaner'],
        function (insertErr) {
          if (insertErr) {
            return res.status(500).json({ message: 'Failed to create cleaner' });
          }
          res.status(201).json({
            message: 'Cleaner created',
            cleaner: {
              id: this.lastID,
              firstName,
              lastName,
              email,
              phone,
              role: 'cleaner'
            }
          });
        }
      );
    });
  });
});

// Admin: assign cleaner and/or update status for an order
app.patch('/api/admin/orders/:id', authenticateToken, authorizeRoles('admin'), express.json(), (req, res) => {
  const orderId = req.params.id;
  const { cleanerId, status } = req.body;

  if (status && !ORDER_STATUSES.includes(status)) {
    return res.status(400).json({ message: 'Invalid status value' });
  }

  const fields = [];
  const params = [];
  if (typeof cleanerId === 'number') {
    fields.push('cleaner_id = ?');
    params.push(cleanerId);
  }
  if (status) {
    fields.push('status = ?');
    params.push(status);
  }
  if (fields.length === 0) {
    return res.status(400).json({ message: 'No changes provided' });
  }
  fields.push('updated_at = CURRENT_TIMESTAMP');

  const sql = `UPDATE orders SET ${fields.join(', ')} WHERE id = ?`;
  params.push(orderId);

  db.run(sql, params, function (err) {
    if (err) {
      console.error('Admin update order error:', err);
      return res.status(500).json({ message: 'Failed to update order' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.json({ message: 'Order updated successfully' });
  });
});

// Admin: create cleaner work schedule
app.post('/api/admin/schedules', authenticateToken, authorizeRoles('admin'), (req, res) => {
  const { cleanerId, work_date, start_time, end_time, note } = req.body || {};
  if (!cleanerId || !work_date || !start_time || !end_time) {
    return res.status(400).json({ message: 'Missing required schedule fields' });
  }
  db.run(
    `INSERT INTO cleaner_schedules (cleaner_id, work_date, start_time, end_time, note)
     VALUES (?, ?, ?, ?, ?)`,
    [cleanerId, work_date, start_time, end_time, note || null],
    function (err) {
      if (err) {
        console.error('Create schedule error:', err);
        return res.status(500).json({ message: 'Failed to create schedule' });
      }
      res.status(201).json({ message: 'Schedule created', id: this.lastID });
    }
  );
});

// Admin: list schedules (optionally filtered by cleaner or date)
app.get('/api/admin/schedules', authenticateToken, authorizeRoles('admin'), (req, res) => {
  const { cleanerId, work_date } = req.query;
  const where = [];
  const params = [];
  if (cleanerId) {
    where.push('cs.cleaner_id = ?');
    params.push(cleanerId);
  }
  if (work_date) {
    where.push('cs.work_date = ?');
    params.push(work_date);
  }
  const sql = `
    SELECT cs.*, c.first_name, c.last_name
    FROM cleaner_schedules cs
    JOIN customers c ON cs.cleaner_id = c.id
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY cs.work_date ASC, cs.start_time ASC
  `;
  db.all(sql, params, (err, rows) => {
    if (err) {
      console.error('List schedules error:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json({
      schedules: rows.map(r => ({
        id: r.id,
        cleaner: { id: r.cleaner_id, firstName: r.first_name, lastName: r.last_name },
        work_date: r.work_date,
        start_time: r.start_time,
        end_time: r.end_time,
        note: r.note
      }))
    });
  });
});

// Cleaner: my schedule
app.get('/api/cleaner/schedules', authenticateToken, authorizeRoles('cleaner'), (req, res) => {
  const cleanerId = req.user.id;
  db.all(
    `SELECT id, work_date, start_time, end_time, note
     FROM cleaner_schedules
     WHERE cleaner_id = ?
     ORDER BY work_date ASC, start_time ASC`,
    [cleanerId],
    (err, rows) => {
      if (err) {
        console.error('Cleaner schedules error:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({ schedules: rows });
    }
  );
});

// Cleaner: orders assigned to me
app.get('/api/cleaner/orders', authenticateToken, authorizeRoles('cleaner'), (req, res) => {
  const cleanerId = req.user.id;
  const sql = `
    SELECT
      o.*,
      c.first_name AS customer_first_name,
      c.last_name AS customer_last_name
    FROM orders o
    JOIN customers c ON o.customer_id = c.id
    WHERE o.cleaner_id = ?
    ORDER BY o.schedule_date ASC, o.schedule_time ASC
  `;
  db.all(sql, [cleanerId], (err, rows) => {
    if (err) {
      console.error('Cleaner orders error:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    const orders = rows.map(row => ({
      id: row.id,
      customer: {
        id: row.customer_id,
        firstName: row.customer_first_name,
        lastName: row.customer_last_name
      },
      property_type: row.property_type,
      rooms: row.rooms,
      bathrooms: row.bathrooms,
      cleaning_type: row.cleaning_type,
      base_price: row.base_price,
      addons: JSON.parse(row.addons),
      total_price: row.total_price,
      schedule_date: row.schedule_date,
      schedule_time: row.schedule_time,
      address: {
        street: row.address_street,
        house: row.address_house,
        apartment: row.address_apartment,
        floor: row.address_floor,
        comment: row.address_comment
      },
      status: row.status,
      created_at: row.created_at,
      updated_at: row.updated_at
    }));
    res.json({ orders, statuses: ORDER_STATUSES });
  });
});

// Cleaner: update status of an assigned order
app.patch('/api/cleaner/orders/:id/status', authenticateToken, authorizeRoles('cleaner'), (req, res) => {
  const cleanerId = req.user.id;
  const orderId = req.params.id;
  const { status } = req.body || {};

  if (!status || !ORDER_STATUSES.includes(status)) {
    return res.status(400).json({ message: 'Invalid status value' });
  }

  // Ensure this order belongs to this cleaner
  db.get('SELECT id FROM orders WHERE id = ? AND cleaner_id = ?', [orderId, cleanerId], (err, row) => {
    if (err) {
      console.error('Cleaner status check error:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (!row) {
      return res.status(404).json({ message: 'Order not found or not assigned to this cleaner' });
    }

    db.run(
      'UPDATE orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [status, orderId],
      function (updateErr) {
        if (updateErr) {
          console.error('Cleaner update status error:', updateErr);
          return res.status(500).json({ message: 'Failed to update status' });
        }
        res.json({ message: 'Status updated' });
      }
    );
  });
});

// Get user orders
app.get('/api/orders', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM orders WHERE customer_id = ? ORDER BY created_at DESC',
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }

      const orders = rows.map(row => ({
        id: row.id,
        property_type: row.property_type,
        rooms: row.rooms,
        bathrooms: row.bathrooms,
        cleaning_type: row.cleaning_type,
        base_price: row.base_price,
        addons: JSON.parse(row.addons),
        total_price: row.total_price,
        schedule_date: row.schedule_date,
        schedule_time: row.schedule_time,
        address: {
          street: row.address_street,
          house: row.address_house,
          apartment: row.address_apartment,
          floor: row.address_floor,
          comment: row.address_comment
        },
        status: row.status,
        created_at: row.created_at
      }));

      res.json({ orders });
    }
  );
});

// Account profile (basic details + city preference)
app.get('/api/account/profile', authenticateToken, (req, res) => {
  db.get(
    'SELECT first_name, last_name, email, phone, city FROM customers WHERE id = ?',
    [req.user.id],
    (err, row) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      if (!row) {
        return res.status(404).json({ message: 'Profile not found' });
      }
      res.json({
        profile: {
          firstName: row.first_name,
          lastName: row.last_name,
          email: row.email,
          phone: row.phone,
          city: row.city || null
        },
        cities: CITY_OPTIONS
      });
    }
  );
});

app.patch('/api/account/profile', authenticateToken, (req, res) => {
  const city = typeof req.body?.city === 'string' ? req.body.city.trim() : '';
  if (!CITY_OPTIONS.includes(city)) {
    return res.status(400).json({ message: 'Invalid city selection' });
  }
  db.run(
    'UPDATE customers SET city = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [city, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ message: 'Failed to update profile' });
      }
      res.json({ message: 'City updated', city });
    }
  );
});

// Account info: distinct addresses used by the customer
app.get('/api/account/addresses', authenticateToken, (req, res) => {
  db.all(
    `SELECT DISTINCT address_street as street, address_house as house, address_apartment as apartment,
            address_floor as floor, address_comment as comment
     FROM orders WHERE customer_id = ? ORDER BY created_at DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({ addresses: rows });
    }
  );
});

// Account info: rewards summary and per-order rewards (e.g., 5% cashback on completed orders)
app.get('/api/account/rewards', authenticateToken, (req, res) => {
  db.all(
    `SELECT id, total_price, status, created_at FROM orders WHERE customer_id = ? ORDER BY created_at DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      const REWARD_RATE = 0.05;
      const rewards = rows.map(r => ({
        orderId: r.id,
        amount: Number((r.total_price * REWARD_RATE).toFixed(2)),
        status: r.status,
        created_at: r.created_at
      }));
      const totalEarned = rewards.reduce((sum, r) => sum + r.amount, 0);
      res.json({ rate: REWARD_RATE, totalEarned: Number(totalEarned.toFixed(2)), rewards });
    }
  );
});

// Serve static files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`API available at http://localhost:${PORT}/api`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0);
  });
});


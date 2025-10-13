const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Middleware
app.use(helmet());
app.use(cors());
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
  // Customers table
  db.run(`CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Orders table
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    property_type TEXT NOT NULL,
    rooms INTEGER NOT NULL,
    bathrooms INTEGER NOT NULL,
    cleaning_type TEXT NOT NULL,
    base_price REAL NOT NULL,
    addons JSON NOT NULL,
    total_price REAL NOT NULL,
    schedule_date TEXT NOT NULL,
    schedule_time TEXT NOT NULL,
    address_street TEXT NOT NULL,
    address_house TEXT NOT NULL,
    address_apartment TEXT,
    address_floor TEXT,
    address_comment TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers (id)
  )`);

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

// Validation schemas
const registerSchema = Joi.object({
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
          'INSERT INTO customers (first_name, last_name, email, phone, password_hash) VALUES (?, ?, ?, ?, ?)',
          [firstName, lastName, email, phone, hash],
          function(err) {
            if (err) {
              return res.status(500).json({ message: 'Failed to create user' });
            }

            const token = jwt.sign(
              { id: this.lastID, email },
              JWT_SECRET,
              { expiresIn: '7d' }
            );

            res.status(201).json({
              message: 'User created successfully',
              token,
              user: {
                id: this.lastID,
                firstName,
                lastName,
                email,
                phone
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

        const token = jwt.sign(
          { id: user.id, email: user.email },
          JWT_SECRET,
          { expiresIn: '7d' }
        );

        res.json({
          message: 'Login successful',
          token,
          user: {
            id: user.id,
            firstName: user.first_name,
            lastName: user.last_name,
            email: user.email,
            phone: user.phone
          }
        });
      });
    });
  } catch (error) {
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

    db.run(
      `INSERT INTO orders (
        customer_id, property_type, rooms, bathrooms, cleaning_type, base_price,
        addons, total_price, schedule_date, schedule_time, address_street,
        address_house, address_apartment, address_floor, address_comment
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id, property_type, rooms, bathrooms, cleaning_type, base_price,
        JSON.stringify(addons), total_price, schedule_date, schedule_time,
        address_street, address_house, address_apartment, address_floor, address_comment
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

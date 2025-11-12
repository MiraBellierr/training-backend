require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const archiver = require('archiver');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = 3001;
const JWT_SECRET = process.env.JWT_TOKEN;

// Initialize SQLite database
const dbPath = path.join(__dirname, 'registrations.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

// Add middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
try {
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('Created uploads directory:', uploadsDir);
  } else {
    console.log('Uploads directory exists:', uploadsDir);
  }
  
  // Check write permissions
  fs.accessSync(uploadsDir, fs.constants.W_OK);
  console.log('Uploads directory is writable');
} catch (error) {
  console.error('ERROR: Cannot create or write to uploads directory:', error);
  console.error('Please check directory permissions');
}

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    try {
      const urlParts = req.url.split('/');
      let uploadFolder;
      
      console.log('Multer destination - URL:', req.url);
      console.log('Multer destination - File field:', file.fieldname);
      
      // Check if this is a news article upload
      if (urlParts.indexOf('news') !== -1) {
        uploadFolder = path.join(__dirname, 'uploads', 'news');
      } 
      // Check if this is an order upload
      else if (urlParts.indexOf('orders') !== -1) {
        const ordersIndex = urlParts.indexOf('orders');
        let orderId = 'temp';
        
        if (ordersIndex !== -1 && urlParts[ordersIndex + 1]) {
          // Extract the ID from URL (e.g., /api/orders/123)
          const potentialId = urlParts[ordersIndex + 1];
          if (!isNaN(potentialId)) {
            orderId = potentialId;
          }
        }
        
        uploadFolder = path.join(__dirname, 'uploads', orderId);
      } 
      // Default fallback
      else {
        uploadFolder = path.join(__dirname, 'uploads', 'misc');
      }
      
      console.log('Upload folder:', uploadFolder);
      
      // Create directory if it doesn't exist
      if (!fs.existsSync(uploadFolder)) {
        fs.mkdirSync(uploadFolder, { recursive: true });
        console.log('Created upload folder:', uploadFolder);
      }
      
      cb(null, uploadFolder);
    } catch (error) {
      console.error('Error in multer destination:', error);
      cb(error, null);
    }
  },
  filename: function (req, file, cb) {
    try {
      // Use original name but make it safe for filesystem
      const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
      const filename = Date.now() + '-' + safeName;
      console.log('Saving file as:', filename);
      cb(null, filename);
    } catch (error) {
      console.error('Error in multer filename:', error);
      cb(error, null);
    }
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    console.log('Multer fileFilter - Field:', file.fieldname, 'Filename:', file.originalname, 'Mimetype:', file.mimetype);
    
    // Allow images and Lighburn files
    if (file.fieldname === 'screenshot' || file.fieldname === 'pictures') {
      if (!file.mimetype.startsWith('image/')) {
        console.log('Rejected: Not an image file');
        return cb(new Error('Only image files are allowed!'));
      }
    } else if (file.fieldname === 'lighburn') {
      if (!file.originalname.endsWith('.lbrn') && !file.originalname.endsWith('.lbrn2')) {
        console.log('Rejected: Not a Lighburn file');
        return cb(new Error('Only Lighburn files (.lbrn, .lbrn2) are allowed!'));
      }
    }
    
    console.log('File accepted');
    cb(null, true);
  }
});

// Helper function to convert absolute path to relative path for database storage
function getRelativePath(absolutePath) {
  if (!absolutePath) return null;
  // Remove the base directory path, keep only uploads/... part
  const uploadsIndex = absolutePath.indexOf('uploads');
  if (uploadsIndex !== -1) {
    return absolutePath.substring(uploadsIndex);
  }
  return absolutePath;
}

// Helper function to get absolute path from relative path
function getAbsolutePath(relativePath) {
  if (!relativePath) return null;
  // If already absolute, return as is
  if (path.isAbsolute(relativePath)) {
    return relativePath;
  }
  return path.join(__dirname, relativePath);
}

// Utility function to clean up old files
async function cleanupOldFiles(orderId) {
  const orderDir = path.join(__dirname, 'uploads', orderId.toString());
  if (fs.existsSync(orderDir)) {
    const currentFiles = await fs.promises.readdir(orderDir);
    for (const file of currentFiles) {
      const filePath = path.join(orderDir, file);
      await fs.promises.unlink(filePath);
    }
  }
}

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Create tables if they don't exist
function initializeDatabase() {
  // Registrations table
  db.run(`
    CREATE TABLE IF NOT EXISTS registrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      email TEXT NOT NULL,
      interests TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating registrations table:', err);
    } else {
      console.log('Registrations table ready');
    }
  });

  // Orders table with new fields
  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_no TEXT UNIQUE NOT NULL,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      collection TEXT NOT NULL,
      order_status TEXT NOT NULL,
      product TEXT NOT NULL,
      price REAL NOT NULL,
      customer_name TEXT NOT NULL,
      phone TEXT NOT NULL,
      city TEXT,
      agensi TEXT,
      agensi_address TEXT,
      sales TEXT NOT NULL,
      due_date TEXT NOT NULL,
      notes TEXT,
      screenshot_path TEXT,
      pictures_path TEXT,
      lighburn_path TEXT,
      carbon_footprint REAL,
      quantity INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating orders table:', err);
    } else {
      console.log('Orders table ready');
      // Add carbon_footprint column if it doesn't exist (for existing databases)
      db.run(`ALTER TABLE orders ADD COLUMN carbon_footprint REAL`, (alterErr) => {
        if (alterErr) {
          // Column might already exist, ignore error
          if (!alterErr.message.includes('duplicate column')) {
            console.error('Note: carbon_footprint column may already exist');
          }
        } else {
          console.log('Added carbon_footprint column to orders table');
        }
      });
      
      // Add quantity column if it doesn't exist (for existing databases)
      db.run(`ALTER TABLE orders ADD COLUMN quantity INTEGER DEFAULT 1`, (alterErr) => {
        if (alterErr) {
          // Column might already exist, ignore error
          if (!alterErr.message.includes('duplicate column')) {
            console.error('Note: quantity column may already exist');
          }
        } else {
          console.log('Added quantity column to orders table');
        }
      });
      
      // Add city column if it doesn't exist (for existing databases)
      db.run(`ALTER TABLE orders ADD COLUMN city TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: city column may already exist');
        }
      });
      
      // Add agensi column if it doesn't exist (for existing databases)
      db.run(`ALTER TABLE orders ADD COLUMN agensi TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: agensi column may already exist');
        }
      });
      
      // Add agensi_address column if it doesn't exist (for existing databases)
      db.run(`ALTER TABLE orders ADD COLUMN agensi_address TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: agensi_address column may already exist');
        } else {
          console.log('Added agensi_address column to orders table');
        }
      });
    }
  });

  // Order products table - for multiple products per order
  db.run(`
    CREATE TABLE IF NOT EXISTS order_products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      product_name TEXT NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 1,
      price REAL NOT NULL,
      deco_box INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
    )
  `, (err) => {
    if (err) {
      console.error('Error creating order_products table:', err);
    } else {
      console.log('Order products table ready');
    }
  });

  // Admin users table
  db.run(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      company TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating admin_users table:', err);
    } else {
      console.log('Admin users table ready');
      
      // Add email, phone, and company columns if they don't exist (for existing databases)
      db.run(`ALTER TABLE admin_users ADD COLUMN email TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: email column may already exist');
        }
      });
      
      db.run(`ALTER TABLE admin_users ADD COLUMN phone TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: phone column may already exist');
        }
      });
      
      db.run(`ALTER TABLE admin_users ADD COLUMN company TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: company column may already exist');
        }
      });
      
      createDefaultAdmin();
    }
  });

  // News articles table
  db.run(`
    CREATE TABLE IF NOT EXISTS news_articles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      excerpt TEXT NOT NULL,
      content TEXT NOT NULL,
      author TEXT NOT NULL,
      category TEXT NOT NULL,
      image_path TEXT,
      featured BOOLEAN DEFAULT 0,
      published BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating news_articles table:', err);
    } else {
      console.log('News articles table ready');
    }
  });
}

function createDefaultAdmin() {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  
  db.get('SELECT * FROM admin_users WHERE username = ?', [username], async (err, row) => {
    if (err) {
      console.error('Error checking for admin:', err);
      return;
    }
    
    if (!row) {
      const passwordHash = await bcrypt.hash(password, 10);
      db.run(
        'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
        [username, passwordHash],
        (err) => {
          if (err) {
            console.error('Error creating default admin:', err);
          } else {
            console.log('Default admin created');
          }
        }
      );
    }
  });
}

// Generate unique order number with INV prefix in format: INVyear_month_numbering
async function generateOrderNumber(db) {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const prefix = `INV${year}_${month}_`;
  
  // Get the count of orders for this month
  return new Promise((resolve, reject) => {
    const sql = `SELECT COUNT(*) as count FROM orders WHERE order_no LIKE ?`;
    db.get(sql, [`${prefix}%`], (err, row) => {
      if (err) {
        reject(err);
      } else {
        const nextNumber = (row.count + 1).toString().padStart(4, '0');
        resolve(`${prefix}${nextNumber}`);
      }
    });
  });
}

// Format date to GMT+8
function formatDateGMT8() {
  const date = new Date();
  const options = { timeZone: 'Asia/Kuching', year: 'numeric', month: '2-digit', day: '2-digit' };
  return date.toLocaleDateString('en-CA', options);
}

// Format time to GMT+8
function formatTimeGMT8() {
  const date = new Date();
  const options = { timeZone: 'Asia/Kuching', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
  return date.toLocaleTimeString('en-US', options);
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// ============= ENDPOINT DECLARATIONS =============

// ============= AUTH ENDPOINTS =============
// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get(
    'SELECT * FROM admin_users WHERE username = ?',
    [username],
    async (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }

      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const validPassword = await bcrypt.compare(password, user.password_hash);
      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate JWT token
      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({
        message: 'Login successful',
        token,
        username: user.username
      });
    }
  );
});

// Create new admin endpoint (PROTECTED)
app.post('/api/admin/create', authenticateToken, async (req, res) => {
  const { username, email, password } = req.body;

  // Validation
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email and password are required' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long' });
  }

  // Check if username already exists
  db.get('SELECT * FROM admin_users WHERE username = ?', [username], async (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Server error' });
    }

    if (row) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    // Insert new admin
    db.run(
      'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash],
      (err) => {
        if (err) {
          console.error('Error creating new admin:', err);
          return res.status(500).json({ error: 'Failed to create admin account' });
        }

        res.status(201).json({
          message: 'Admin account created successfully'
        });
      }
    );
  });
});

// Verify token endpoint
app.get('/api/admin/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, username: req.user.username });
});

// Change password endpoint
app.post('/api/admin/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  db.get(
    'SELECT * FROM admin_users WHERE id = ?',
    [req.user.id],
    async (err, user) => {
      if (err || !user) {
        return res.status(500).json({ error: 'Server error' });
      }

      const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
      if (!validPassword) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 10);
      db.run(
        'UPDATE admin_users SET password_hash = ? WHERE id = ?',
        [newPasswordHash, req.user.id],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to update password' });
          }
          res.json({ message: 'Password updated successfully' });
        }
      );
    }
  );
});

// Get admin profile endpoint (PROTECTED)
app.get('/api/admin/profile', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, username, email, phone, company, created_at FROM admin_users WHERE id = ?',
    [req.user.id],
    (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({
        username: user.username,
        email: user.email || `${user.username}@aanguscraft.com`,
        phone: user.phone || '+60123456789',
        role: 'Administrator',
        company: user.company || 'Aangus Craft',
        created_at: user.created_at
      });
    }
  );
});

// Update admin profile endpoint (PROTECTED)
app.put('/api/admin/profile', authenticateToken, async (req, res) => {
  const { username, email, phone, company } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  // Validate email format if provided
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  // Validate phone format if provided (basic validation)
  if (phone && phone.length < 10) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }

  // Check if new username is already taken by another user
  db.get(
    'SELECT * FROM admin_users WHERE username = ? AND id != ?',
    [username, req.user.id],
    (err, existingUser) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }

      if (existingUser) {
        return res.status(400).json({ error: 'Username already taken' });
      }

      // Check if new email is already taken by another user
      if (email) {
        db.get(
          'SELECT * FROM admin_users WHERE email = ? AND id != ?',
          [email, req.user.id],
          (err, existingEmail) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Server error' });
            }

            if (existingEmail) {
              return res.status(400).json({ error: 'Email already in use' });
            }

            // Update all profile fields
            db.run(
              'UPDATE admin_users SET username = ?, email = ?, phone = ?, company = ? WHERE id = ?',
              [username, email, phone, company, req.user.id],
              (err) => {
                if (err) {
                  console.error('Error updating profile:', err);
                  return res.status(500).json({ error: 'Failed to update profile' });
                }

                res.json({
                  message: 'Profile updated successfully',
                  username: username,
                  email: email,
                  phone: phone,
                  company: company
                });
              }
            );
          }
        );
      } else {
        // Update without email validation
        db.run(
          'UPDATE admin_users SET username = ?, email = ?, phone = ?, company = ? WHERE id = ?',
          [username, email, phone, company, req.user.id],
          (err) => {
            if (err) {
              console.error('Error updating profile:', err);
              return res.status(500).json({ error: 'Failed to update profile' });
            }

            res.json({
              message: 'Profile updated successfully',
              username: username,
              email: email,
              phone: phone,
              company: company
            });
          }
        );
      }
    }
  );
});

// List all admin users endpoint (PROTECTED)
app.get('/api/admin/list', authenticateToken, (req, res) => {
  const sql = 'SELECT id, username, email, phone, company, created_at FROM admin_users ORDER BY created_at DESC';

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Error fetching admins:', err);
      return res.status(500).json({ error: 'Failed to fetch admin users' });
    }

    // Format the response
    const admins = rows.map(admin => ({
      id: admin.id,
      username: admin.username,
      email: admin.email || `${admin.username}@aanguscraft.com`,
      phone: admin.phone || '',
      company: admin.company || '',
      created_at: admin.created_at
    }));

    res.json(admins);
  });
});

// Delete admin user endpoint (PROTECTED)
app.delete('/api/admin/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  // Prevent self-deletion
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }

  const sql = 'DELETE FROM admin_users WHERE id = ?';

  db.run(sql, [id], function(err) {
    if (err) {
      console.error('Error deleting admin:', err);
      return res.status(500).json({ error: 'Failed to delete admin user' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Admin user not found' });
    }

    res.json({ message: 'Admin user deleted successfully' });
  });
});

// ============= REGISTRATION ENDPOINTS =============
// POST endpoint to register new user (PUBLIC)
app.post('/api/register', (req, res) => {
  const { name, phone, email, interests } = req.body;

  // Validation
  if (!name || !phone || !email || !interests || interests.length === 0) {
    return res.status(400).json({ 
      error: 'All fields are required and at least one interest must be selected' 
    });
  }

  // Convert interests array to comma-separated string
  const interestsString = interests.join(',');

  const sql = `
    INSERT INTO registrations (name, phone, email, interests) 
    VALUES (?, ?, ?, ?)
  `;

  db.run(sql, [name, phone, email, interestsString], function(err) {
    if (err) {
      console.error('Error inserting data:', err);
      return res.status(500).json({ error: 'Failed to save registration' });
    }

    res.status(201).json({
      message: 'Registration successful',
      id: this.lastID
    });
  });
});

// GET endpoint to retrieve all registrations (PROTECTED)
app.get('/api/registrations', authenticateToken, (req, res) => {
  const sql = 'SELECT * FROM registrations ORDER BY created_at DESC';

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Error fetching data:', err);
      return res.status(500).json({ error: 'Failed to fetch registrations' });
    }

    // Convert interests string back to array
    const formattedRows = rows.map(row => ({
      ...row,
      interests: row.interests.split(',')
    }));

    res.json(formattedRows);
  });
});

// GET endpoint to retrieve single registration by ID (PROTECTED)
app.get('/api/registrations/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM registrations WHERE id = ?';

  db.get(sql, [id], (err, row) => {
    if (err) {
      console.error('Error fetching data:', err);
      return res.status(500).json({ error: 'Failed to fetch registration' });
    }

    if (!row) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    res.json({
      ...row,
      interests: row.interests.split(',')
    });
  });
});

// DELETE endpoint to remove a registration (PROTECTED)
app.delete('/api/registrations/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM registrations WHERE id = ?';

  db.run(sql, [id], function(err) {
    if (err) {
      console.error('Error deleting data:', err);
      return res.status(500).json({ error: 'Failed to delete registration' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    res.json({ message: 'Registration deleted successfully' });
  });
});

// ============= ORDERS ENDPOINTS =============
// GET endpoint to retrieve all orders (PROTECTED)
app.get('/api/orders', authenticateToken, (req, res) => {
  const sql = 'SELECT * FROM orders ORDER BY created_at DESC';

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Error fetching orders:', err);
      return res.status(500).json({ error: 'Failed to fetch orders' });
    }

    // Fetch products for each order
    const ordersWithProducts = [];
    let processedCount = 0;

    if (rows.length === 0) {
      return res.json([]);
    }

    rows.forEach(order => {
      const productsSql = 'SELECT * FROM order_products WHERE order_id = ?';
      db.all(productsSql, [order.id], (prodErr, products) => {
        if (!prodErr) {
          order.products = products || [];
        }
        ordersWithProducts.push(order);
        processedCount++;

        // When all orders are processed, send response
        if (processedCount === rows.length) {
          res.json(ordersWithProducts);
        }
      });
    });
  });
});

// GET endpoint to retrieve single order by ID (PROTECTED)
app.get('/api/orders/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM orders WHERE id = ?';

  db.get(sql, [id], (err, row) => {
    if (err) {
      console.error('Error fetching order:', err);
      return res.status(500).json({ error: 'Failed to fetch order' });
    }

    if (!row) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Fetch products for this order
    const productsSql = 'SELECT * FROM order_products WHERE order_id = ?';
    db.all(productsSql, [id], (prodErr, products) => {
      if (prodErr) {
        console.error('Error fetching products:', prodErr);
        return res.status(500).json({ error: 'Failed to fetch products' });
      }

      // Attach products to order
      row.products = products || [];
      res.json(row);
    });
  });
});

// GET endpoint to retrieve products for an order (PROTECTED)
app.get('/api/orders/:id/products', authenticateToken, (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM order_products WHERE order_id = ?';

  db.all(sql, [id], (err, rows) => {
    if (err) {
      console.error('Error fetching products:', err);
      return res.status(500).json({ error: 'Failed to fetch products' });
    }

    res.json(rows);
  });
});

// GET endpoint to retrieve unique customers with their details (PROTECTED)
app.get('/api/customers', authenticateToken, (req, res) => {
  const sql = `
    SELECT DISTINCT 
      customer_name, 
      phone, 
      city, 
      agensi,
      agensi_address,
      MAX(created_at) as last_order_date
    FROM orders 
    GROUP BY customer_name, phone, city, agensi, agensi_address
    ORDER BY last_order_date DESC
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Error fetching customers:', err);
      return res.status(500).json({ error: 'Failed to fetch customers' });
    }

    res.json(rows);
  });
});

// POST endpoint to create new order (PROTECTED) - Step 1: Create order without files
app.post('/api/orders', authenticateToken, async (req, res) => {
  console.log('Received order creation request');
  console.log('Body:', req.body);
  
  const { collection, orderStatus, products, customerName, phone, city, agensi, agensiAddress, sales, notes, dueDate } = req.body;

  // Validation
  if (!collection || !orderStatus || !customerName || !phone || !sales || !dueDate) {
    return res.status(400).json({ error: 'Required fields are missing' });
  }

  // Validate products array
  if (!products || !Array.isArray(products) || products.length === 0) {
    return res.status(400).json({ error: 'At least one product is required' });
  }

  // Validate each product
  let totalPrice = 0;
  for (const prod of products) {
    if (!prod.productName || !prod.price || !prod.quantity) {
      return res.status(400).json({ error: 'Each product must have name, price, and quantity' });
    }
    const price = parseFloat(prod.price);
    const quantity = parseInt(prod.quantity);
    if (isNaN(price) || price < 0 || isNaN(quantity) || quantity < 1) {
      return res.status(400).json({ error: 'Invalid price or quantity in products' });
    }
    totalPrice += price * quantity;
  }

  // Validate phone number
  if (!phone.startsWith('+60')) {
    return res.status(400).json({ error: 'Phone number must start with +60' });
  }

  // Generate order details
  let orderNo;
  try {
    orderNo = await generateOrderNumber(db);
  } catch (err) {
    console.error('Error generating order number:', err);
    return res.status(500).json({ error: 'Failed to generate order number' });
  }
  const date = formatDateGMT8();
  const time = formatTimeGMT8();

  // For backward compatibility, store first product in orders table
  const firstProduct = products[0];
  const legacyProduct = firstProduct.productName;
  const legacyPrice = parseFloat(firstProduct.price);
  const legacyQuantity = parseInt(firstProduct.quantity);

  // Insert order WITHOUT file paths first
  const sql = `
    INSERT INTO orders (
      order_no, date, time, collection, order_status, product, 
      price, customer_name, phone, city, agensi, agensi_address, sales, notes, due_date, quantity
    ) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(sql, [
    orderNo, date, time, collection, orderStatus, legacyProduct,
    totalPrice, customerName, phone, city || null, agensi || null, agensiAddress || null, sales, notes || null, dueDate, legacyQuantity
  ], function(err) {
    if (err) {
      console.error('Error inserting order:', err);
      return res.status(500).json({ error: 'Failed to create order' });
    }

    const orderId = this.lastID;
    console.log('Order created with ID:', orderId);

    // Insert all products into order_products table
    const productSql = `INSERT INTO order_products (order_id, product_name, quantity, price, deco_box) VALUES (?, ?, ?, ?, ?)`;
    let productsInserted = 0;
    let insertError = null;

    products.forEach((prod, index) => {
      const decoBox = prod.decoBox ? 1 : 0;
      db.run(productSql, [orderId, prod.productName, parseInt(prod.quantity), parseFloat(prod.price), decoBox], (prodErr) => {
        if (prodErr) {
          console.error('Error inserting product:', prodErr);
          insertError = prodErr;
        }
        productsInserted++;

        // When all products are processed
        if (productsInserted === products.length) {
          if (insertError) {
            return res.status(500).json({ error: 'Failed to insert products' });
          }

          res.status(201).json({
            message: 'Order created successfully',
            order: {
              id: orderId,
              order_no: orderNo,
              date,
              time,
              collection,
              order_status: orderStatus,
              products: products,
              total_price: totalPrice,
              customer_name: customerName,
              phone,
              sales,
              notes,
              due_date: dueDate
            }
          });
        }
      });
    });
  });
});

// POST endpoint to upload screenshot for an order (PROTECTED)
app.post('/api/orders/:id/upload/screenshot', authenticateToken, upload.fields([
  { name: 'screenshot', maxCount: 100 }
]), (req, res) => {
  const { id } = req.params;
  console.log('Received screenshot upload request for order:', id);

  const files = req.files;
  if (!files?.screenshot?.[0]) {
    return res.status(400).json({ error: 'No screenshot file uploaded' });
  }

  const screenshotPath = files.screenshot[0].path;
  const relativeScreenshotPath = getRelativePath(screenshotPath);

  const sql = `UPDATE orders SET screenshot_path = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;

  db.run(sql, [relativeScreenshotPath, id], function(err) {
    if (err) {
      console.error('Error updating order with screenshot:', err);
      return res.status(500).json({ error: 'Failed to update order with screenshot' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    console.log('Successfully updated order', id, 'with screenshot');
    res.json({
      message: 'Screenshot uploaded successfully',
      screenshot_path: relativeScreenshotPath
    });
  });
});

// POST endpoint to upload pictures for an order (PROTECTED)
app.post('/api/orders/:id/upload/pictures', authenticateToken, upload.fields([
  { name: 'pictures', maxCount: 100 }
]), (req, res) => {
  const { id } = req.params;
  console.log('Received pictures upload request for order:', id);

  const files = req.files;
  if (!files?.pictures || files.pictures.length === 0) {
    return res.status(400).json({ error: 'No pictures uploaded' });
  }

  const picturesPath = files.pictures.map(file => file.path).join(',');
  const relativePicturesPath = getRelativePath(picturesPath);

  const sql = `UPDATE orders SET pictures_path = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;

  db.run(sql, [relativePicturesPath, id], function(err) {
    if (err) {
      console.error('Error updating order with pictures:', err);
      return res.status(500).json({ error: 'Failed to update order with pictures' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    console.log('Successfully updated order', id, 'with pictures');
    res.json({
      message: 'Pictures uploaded successfully',
      pictures_path: relativePicturesPath
    });
  });
});

// POST endpoint to upload lighburn file for an order (PROTECTED)
app.post('/api/orders/:id/upload/lighburn', authenticateToken, upload.fields([
  { name: 'lighburn', maxCount: 100 }
]), (req, res) => {
  const { id } = req.params;
  console.log('Received lighburn upload request for order:', id);

  const files = req.files;
  if (!files?.lighburn?.[0]) {
    return res.status(400).json({ error: 'No lighburn file uploaded' });
  }

  const lighburnPath = files.lighburn[0].path;
  const relativeLighburnPath = getRelativePath(lighburnPath);

  const sql = `UPDATE orders SET lighburn_path = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;

  db.run(sql, [relativeLighburnPath, id], function(err) {
    if (err) {
      console.error('Error updating order with lighburn file:', err);
      return res.status(500).json({ error: 'Failed to update order with lighburn file' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    console.log('Successfully updated order', id, 'with lighburn file');
    res.json({
      message: 'Lighburn file uploaded successfully',
      lighburn_path: relativeLighburnPath
    });
  });
});

// PUT endpoint to update order data only (PROTECTED) - files uploaded separately
app.put('/api/orders/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { collection, orderStatus, products, customerName, phone, city, agensi, agensiAddress, sales, notes, dueDate, carbonFootprint } = req.body;

  // Validation
  if (!collection || !orderStatus || !customerName || !phone || !sales || !dueDate) {
    return res.status(400).json({ error: 'Required fields are missing' });
  }

  // Validate products array
  if (!products || !Array.isArray(products) || products.length === 0) {
    return res.status(400).json({ error: 'At least one product is required' });
  }

  // Validate each product
  let totalPrice = 0;
  for (const prod of products) {
    if (!prod.productName || !prod.price || !prod.quantity) {
      return res.status(400).json({ error: 'Each product must have name, price, and quantity' });
    }
    const price = parseFloat(prod.price);
    const quantity = parseInt(prod.quantity);
    if (isNaN(price) || price < 0 || isNaN(quantity) || quantity < 1) {
      return res.status(400).json({ error: 'Invalid price or quantity in products' });
    }
    totalPrice += price * quantity;
  }

  // Validate phone number
  if (!phone.startsWith('+60')) {
    return res.status(400).json({ error: 'Phone number must start with +60' });
  }

  // Parse carbon footprint if provided
  const carbonFootprintNum = carbonFootprint ? parseFloat(carbonFootprint) : null;
  if (carbonFootprint && (isNaN(carbonFootprintNum) || carbonFootprintNum < 0)) {
    return res.status(400).json({ error: 'Invalid carbon footprint value' });
  }

  try {
    // For backward compatibility, store first product in orders table
    const firstProduct = products[0];
    const legacyProduct = firstProduct.productName;
    const legacyPrice = parseFloat(firstProduct.price);
    const legacyQuantity = parseInt(firstProduct.quantity);

    const sql = `
      UPDATE orders 
      SET collection = ?, order_status = ?, product = ?, price = ?, 
          customer_name = ?, phone = ?, city = ?, agensi = ?, agensi_address = ?, sales = ?, notes = ?, due_date = ?,
          carbon_footprint = ?, quantity = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `;

    const values = [
      collection, orderStatus, legacyProduct, totalPrice,
      customerName, phone, city || null, agensi || null, agensiAddress || null, sales, notes || null, dueDate,
      carbonFootprintNum, legacyQuantity,
      id
    ];

    db.run(sql, values, function(err) {
      if (err) {
        console.error('Error updating order:', err);
        return res.status(500).json({ error: 'Failed to update order' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Order not found' });
      }

      // Delete existing products and insert new ones
      db.run('DELETE FROM order_products WHERE order_id = ?', [id], (delErr) => {
        if (delErr) {
          console.error('Error deleting old products:', delErr);
          return res.status(500).json({ error: 'Failed to update products' });
        }

        // Insert all products
        const productSql = `INSERT INTO order_products (order_id, product_name, quantity, price, deco_box) VALUES (?, ?, ?, ?, ?)`;
        let productsInserted = 0;
        let insertError = null;

        products.forEach((prod) => {
          const decoBox = prod.decoBox ? 1 : 0;
          db.run(productSql, [id, prod.productName, parseInt(prod.quantity), parseFloat(prod.price), decoBox], (prodErr) => {
            if (prodErr) {
              console.error('Error inserting product:', prodErr);
              insertError = prodErr;
            }
            productsInserted++;

            // When all products are processed
            if (productsInserted === products.length) {
              if (insertError) {
                return res.status(500).json({ error: 'Failed to insert products' });
              }

              res.json({ message: 'Order updated successfully' });
            }
          });
        });
      });
    });
  } catch (err) {
    console.error('Error updating order:', err);
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// DELETE endpoint to remove an order and its files (PROTECTED)
app.delete('/api/orders/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Clean up files first
    await cleanupOldFiles(id);

    const sql = 'DELETE FROM orders WHERE id = ?';
    db.run(sql, [id], function(err) {
      if (err) {
        console.error('Error deleting order:', err);
        return res.status(500).json({ error: 'Failed to delete order' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Order not found' });
      }

      res.json({ message: 'Order deleted successfully' });
    });
  } catch (err) {
    console.error('Error during file cleanup:', err);
    res.status(500).json({ error: 'Failed to delete order' });
  }
});

// Download files endpoint (PROTECTED) - returns zip for multiple files
app.get('/api/orders/:id/files/:type', authenticateToken, (req, res) => {
  const { id, type } = req.params;
  
  const sql = 'SELECT * FROM orders WHERE id = ?';
  db.get(sql, [id], (err, order) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch order' });
    }
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    let relativePaths = [];
    let zipFileName = '';
    
    switch (type) {
      case 'screenshot':
        if (order.screenshot_path) {
          relativePaths = order.screenshot_path.split(',').filter(p => p);
        }
        zipFileName = `order_${order.order_no}_screenshots.zip`;
        break;
      case 'pictures':
        if (order.pictures_path) {
          relativePaths = order.pictures_path.split(',').filter(p => p);
        }
        zipFileName = `order_${order.order_no}_pictures.zip`;
        break;
      case 'lighburn':
        if (order.lighburn_path) {
          relativePaths = order.lighburn_path.split(',').filter(p => p);
        }
        zipFileName = `order_${order.order_no}_lighburn.zip`;
        break;
      default:
        return res.status(400).json({ error: 'Invalid file type' });
    }

    if (relativePaths.length === 0) {
      return res.status(404).json({ error: 'No files found' });
    }

    // Convert relative paths to absolute paths
    const absolutePaths = relativePaths.map(relativePath => getAbsolutePath(relativePath));
    
    // Debug logging
    console.log('File type:', type);
    console.log('Relative paths:', relativePaths);
    console.log('Absolute paths:', absolutePaths);
    
    // Check if they exist
    const existingPaths = absolutePaths.filter(p => fs.existsSync(p));
    
    if (existingPaths.length === 0) {
      console.error('No files found on server');
      console.error('Checked paths:', absolutePaths);
      return res.status(404).json({ error: 'Files not found on server' });
    }

    // If only one file, send it directly
    if (existingPaths.length === 1) {
      // For lighburn files, rename as ORDER_NO_PRODUCT_NAME.extension
      if (type === 'lighburn') {
        const fileExtension = path.extname(existingPaths[0]); // .lbrn or .lbrn2
        const downloadName = `${order.order_no}_${order.product}${fileExtension}`;
        console.log('Lighburn download - Original file:', existingPaths[0]);
        console.log('Lighburn download - Extension:', fileExtension);
        console.log('Lighburn download - Download name:', downloadName);
        
        // Explicitly set Content-Disposition header for CORS
        res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);
        res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');
        return res.download(existingPaths[0], downloadName);
      }
      
      const originalFilename = path.basename(existingPaths[0]);
      res.setHeader('Content-Disposition', `attachment; filename="${originalFilename}"`);
      res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');
      return res.download(existingPaths[0]);
    }

    // Multiple files - create zip
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${zipFileName}"`);

    const archive = archiver('zip', {
      zlib: { level: 9 } // Maximum compression
    });

    archive.on('error', (err) => {
      console.error('Archive error:', err);
      res.status(500).json({ error: 'Failed to create zip file' });
    });

    // Pipe archive to response
    archive.pipe(res);

    // Add files to archive
    existingPaths.forEach((filePath, index) => {
      let fileName = path.basename(filePath);
      
      // For lighburn files, rename as ORDER_NO_PRODUCT_NAME.extension
      if (type === 'lighburn') {
        const fileExtension = path.extname(filePath);
        fileName = `${order.order_no}_${order.product}${fileExtension}`;
      }
      
      archive.file(filePath, { name: fileName });
    });

    // Finalize archive
    archive.finalize();
  });
});

// ============= NEWS ENDPOINTS =============
// GET all news articles (PUBLIC - for news page)
app.get('/api/news', (req, res) => {
  const sql = 'SELECT * FROM news_articles WHERE published = 1 ORDER BY created_at DESC';
  
  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch news articles' });
    }
    res.json(rows);
  });
});

// GET single news article by ID (PUBLIC)
app.get('/api/news/:id', (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM news_articles WHERE id = ? AND published = 1';
  
  db.get(sql, [id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch article' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Article not found' });
    }
    res.json(row);
  });
});

// GET all news articles for admin (PROTECTED)
app.get('/api/admin/news', authenticateToken, (req, res) => {
  const sql = 'SELECT * FROM news_articles ORDER BY created_at DESC';
  
  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch news articles' });
    }
    res.json(rows);
  });
});

// POST create new news article (PROTECTED)
app.post('/api/admin/news', authenticateToken, upload.single('image'), (req, res) => {
  const { title, excerpt, content, category, featured, published } = req.body;
  
  // Validation
  if (!title || !excerpt || !content || !category) {
    return res.status(400).json({ error: 'Title, excerpt, content, and category are required' });
  }
  
  const author = req.user.username;
  const imagePath = req.file ? getRelativePath(req.file.path) : null;
  const isFeatured = featured === 'true' || featured === true ? 1 : 0;
  const isPublished = published === 'true' || published === true ? 1 : 0;
  
  const sql = `
    INSERT INTO news_articles (title, excerpt, content, author, category, image_path, featured, published)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;
  
  db.run(sql, [title, excerpt, content, author, category, imagePath, isFeatured, isPublished], function(err) {
    if (err) {
      console.error('Error creating news article:', err);
      return res.status(500).json({ error: 'Failed to create article' });
    }
    
    res.status(201).json({
      message: 'Article created successfully',
      id: this.lastID
    });
  });
});

// PUT update news article (PROTECTED)
app.put('/api/admin/news/:id', authenticateToken, upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { title, excerpt, content, category, featured, published } = req.body;
  
  // Validation
  if (!title || !excerpt || !content || !category) {
    return res.status(400).json({ error: 'Title, excerpt, content, and category are required' });
  }
  
  const imagePath = req.file ? getRelativePath(req.file.path) : undefined;
  const isFeatured = featured === 'true' || featured === true ? 1 : 0;
  const isPublished = published === 'true' || published === true ? 1 : 0;
  
  // Build update query dynamically based on whether image is uploaded
  let sql, params;
  if (imagePath) {
    sql = `
      UPDATE news_articles 
      SET title = ?, excerpt = ?, content = ?, category = ?, image_path = ?, 
          featured = ?, published = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `;
    params = [title, excerpt, content, category, imagePath, isFeatured, isPublished, id];
  } else {
    sql = `
      UPDATE news_articles 
      SET title = ?, excerpt = ?, content = ?, category = ?, 
          featured = ?, published = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `;
    params = [title, excerpt, content, category, isFeatured, isPublished, id];
  }
  
  db.run(sql, params, function(err) {
    if (err) {
      console.error('Error updating news article:', err);
      return res.status(500).json({ error: 'Failed to update article' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Article not found' });
    }
    
    res.json({ message: 'Article updated successfully' });
  });
});

// DELETE news article (PROTECTED)
app.delete('/api/admin/news/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  
  // First get the article to delete its image
  db.get('SELECT image_path FROM news_articles WHERE id = ?', [id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch article' });
    }
    
    // Delete the article
    db.run('DELETE FROM news_articles WHERE id = ?', [id], function(deleteErr) {
      if (deleteErr) {
        return res.status(500).json({ error: 'Failed to delete article' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Article not found' });
      }
      
      // Delete associated image file if exists
      if (row && row.image_path) {
        const imagePath = getAbsolutePath(row.image_path);
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      }
      
      res.json({ message: 'Article deleted successfully' });
    });
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware for multer
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error('Multer error:', err);
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File size too large. Maximum is 10MB.' });
    }
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  } else if (err) {
    console.error('General error:', err);
    return res.status(500).json({ error: err.message || 'An error occurred' });
  }
  next();
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('='.repeat(50));
  console.log('📝 Registration endpoints:');
  console.log(`   POST   http://localhost:${PORT}/api/register (public)`);
  console.log('');
  console.log('🔐 Admin endpoints:');
  console.log(`   POST   http://localhost:${PORT}/api/admin/login`);
  console.log(`   POST   http://localhost:${PORT}/api/admin/create`);
  console.log(`   GET    http://localhost:${PORT}/api/admin/verify`);
  console.log(`   GET    http://localhost:${PORT}/api/admin/profile`);
  console.log(`   PUT    http://localhost:${PORT}/api/admin/profile`);
  console.log(`   GET    http://localhost:${PORT}/api/admin/list`);
  console.log(`   DELETE http://localhost:${PORT}/api/admin/:id`);
  console.log(`   POST   http://localhost:${PORT}/api/admin/change-password`);
  console.log('');
  console.log('📊 Protected registration endpoints (require auth):');
  console.log(`   GET    http://localhost:${PORT}/api/registrations`);
  console.log(`   GET    http://localhost:${PORT}/api/registrations/:id`);
  console.log(`   DELETE http://localhost:${PORT}/api/registrations/:id`);
  console.log('');
  console.log('🛒 Protected order endpoints (require auth):');
  console.log(`   POST   http://localhost:${PORT}/api/orders`);
  console.log(`   GET    http://localhost:${PORT}/api/orders`);
  console.log(`   GET    http://localhost:${PORT}/api/orders/:id`);
  console.log(`   GET    http://localhost:${PORT}/api/customers`);
  console.log(`   PUT    http://localhost:${PORT}/api/orders/:id`);
  console.log(`   DELETE http://localhost:${PORT}/api/orders/:id`);
  console.log(`   GET    http://localhost:${PORT}/api/orders/:id/files/:type`);
  console.log('');
  console.log('📰 News endpoints:');
  console.log(`   GET    http://localhost:${PORT}/api/news (public)`);
  console.log(`   GET    http://localhost:${PORT}/api/news/:id (public)`);
  console.log(`   GET    http://localhost:${PORT}/api/admin/news (protected)`);
  console.log(`   POST   http://localhost:${PORT}/api/admin/news (protected)`);
  console.log(`   PUT    http://localhost:${PORT}/api/admin/news/:id (protected)`);
  console.log(`   DELETE http://localhost:${PORT}/api/admin/news/:id (protected)`);
  console.log('='.repeat(50));
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('Database connection closed');
    }
    process.exit(0);
  });
});
// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const mysql = require('mysql');
const session = require('express-session');
const path = require('path');

const app = express();
const port = 3000;

// MySQL database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '', // replace with your MySQL password
    database: 'collection_db',
    port: 3307
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL');
});

const multer = require('multer');
const fs = require('fs');

// Store uploads in public/uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        let folder = 'others';
        if (file.fieldname === 'photos') {
            folder = 'photos';
        } else if (file.fieldname === 'documents') {
            folder = 'documents';
        }

        const uploadPath = path.join(__dirname, 'public', 'uploads', folder);
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const decodedOriginalName = Buffer.from(file.originalname, 'latin1').toString('utf8');

        const now = new Date();
        const day = String(now.getDate()).padStart(2, '0');
        const month = String(now.getMonth() + 1).padStart(2, '0'); // Months are zero-based
        const year = now.getFullYear();

        const formattedDate = `${day}-${month}-${year}`;
        const uniqueName = /* Date.now() */formattedDate + '___' + decodedOriginalName;
        cb(null, uniqueName);
    }
});
const upload = multer({ storage });

app.use('/public', express.static(path.join(__dirname, 'public')));


// Middleware
app.use(express.json());
//app.use(express.static('public')); 

app.use('/public', express.static(path.join(__dirname, 'public')));
// Serve static files (HTML, CSS)
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
}));
// Serve the registration page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});
app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Register API
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Check if the username already exists
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.status(500).send('Server error');
        }

        if (results.length > 0) {
            return res.status(400).send('Username already exists');
        }

        // Hash the password before saving it
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).send('Error hashing password');
            }

            // Insert new user into the database
            db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, result) => {
                if (err) {
                    return res.status(500).send('Error registering user');
                }

                res.status(200).send('Registration successful');
            });
        });
    });
});

// Serve the login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/add-item', isLoggedIn, (req, res) => res.sendFile(path.join(__dirname, 'public', 'add-item.html')));

app.get('/forum', isLoggedIn, (req, res) => res.sendFile(path.join(__dirname, 'public', 'forum.html')));

// Serve the main collection page (after login)

//app.get('/', (req, res) => {
//    if (req.session.userId) {
//        res.sendFile(path.join(__dirname, 'public', 'index.html'));
//    } else {
//        res.redirect('/login');
//    }
//});

app.get('/index', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});
app.get('/home_test', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home_test.html'));
});
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


app.get('/user', (req, res) => {
    if (req.session.username) {
        res.json({ username: req.session.username });
    } else {
        res.json({ username: null });
    }
});

// Login API
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(401).send('Invalid credentials');
        }

        const user = results[0];

        // Compare the hashed password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (isMatch) {
                req.session.userId = user.id;
                req.session.username = user.username;
                res.send('Login successful');
            } else {
                res.status(401).send('Invalid credentials');
            }
        });
    });
});

// Logout API
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.send('Logged out successfully');
    });
});

// Protect collection routes (user must be logged in)
function isLoggedIn(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
}

// Routes for managing collection items
app.use('/items', isLoggedIn);

// Create item
app.post('/items', isLoggedIn, upload.fields([
    { name: 'photos', maxCount: 10 },
    { name: 'documents', maxCount: 10 }
]), (req, res) => {
    const { name, description, acquisition_date, cost, origin, brand, model, type } = req.body;
    const userId = req.session.userId;

    const photos = (req.files.photos || []).map(file => `/public/uploads/photos/${file.filename}`).join(',');
    const documents = (req.files.documents || []).map(file => `/public/uploads/documents/${file.filename}`).join(',');
    const query = `
      INSERT INTO items 
      (name, description, acquisition_date, cost, origin, documents, brand, model, photos, type, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [name, description, acquisition_date, cost, origin, documents, brand, model, photos, type, userId];

    db.query(query, values, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error inserting item');
        }
        console.log('Inserted item:', {
            id: result.insertId, // This is the new item's ID
            name,
            description,
            acquisition_date,
            cost,
            origin,
            documents,
            brand,
            model,
            photos,
            type,
            userId
        });
        res.status(200).send('Item added successfully');
    });
});




// Read items (with optional search)
// Fetch items for the logged-in user
app.get('/items', isLoggedIn, (req, res) => {
    const searchQuery = req.query.search || '';
    const allowedFields = ['name', 'description', 'brand', 'model', 'origin']; // whitelist

    const field = allowedFields.includes(req.query.field) ? req.query.field : 'name'; // fallback to name

    const query = `SELECT * FROM items WHERE user_id = ? AND ${field} LIKE ?`;
    const values = [req.session.userId, `%${searchQuery}%`];

    db.query(query, values, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error fetching items');
        }
        res.json(results);
    });
});

// Fetch items for logged in user FORUM
app.get('/itemsForum', isLoggedIn, (req, res) => {
    const searchQuery = req.query.search || '';

    // ✅ Now includes 'username' as allowed search field
    const allowedFields = ['name', 'description', 'brand', 'model', 'origin', 'username'];

    const field = allowedFields.includes(req.query.field) ? req.query.field : 'name';

    // ✅ Proper table prefixing
    const fieldMap = {
        name: 'items.name',
        description: 'items.description',
        brand: 'items.brand',
        model: 'items.model',
        origin: 'items.origin',
        username: 'users.username'
    };

    const dbField = fieldMap[field];

    const query = `
        SELECT items.*, users.username 
        FROM items 
        JOIN users ON items.user_id = users.id 
        WHERE items.type = 'public' AND ${dbField} LIKE ?
    `;
    const values = [`%${searchQuery}%`];

    db.query(query, values, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error fetching items');
        }
        res.json(results);
    });
});





/* // Get single item
app.get('/items/:id', async (req, res) => {
    const item = await db.getItemById(req.params.id); // replace with your logic
    res.json(item);
  });
  
  // Update item
  app.put('/items/:id', async (req, res) => {
    const updated = await db.updateItem(req.params.id, req.body); // replace with your logic
    res.json(updated);
  }); */

// Get single item by ID
app.get('/items/:id', isLoggedIn, (req, res) => {
    const itemId = req.params.id;

    db.query('SELECT * FROM items WHERE id = ? AND user_id = ?', [itemId, req.session.userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error retrieving item');
        }

        if (results.length === 0) {
            return res.status(404).send('Item not found');
        }

        res.json(results[0]);
    });
});


// Update an item
// Update an item
app.put('/items/:id', isLoggedIn, upload.fields([
    { name: 'photos', maxCount: 10 },
    { name: 'documents', maxCount: 10 }
]), (req, res) => {
    const itemId = req.params.id;
    const updatedItem = req.body;

    const existingPhotos = req.body.existingPhotos ? JSON.parse(req.body.existingPhotos) : [];
    const newPhotos = (req.files.photos || []).map(file => `/public/uploads/photos/${file.filename}`);
    const allPhotos = [...existingPhotos, ...newPhotos];

    //const existingDocuments = req.body.existingDocuments ? JSON.parse(req.body.existingDocuments) : [];
    let existingDocuments = [];
    try {
        existingDocuments = JSON.parse(req.body.existingDocuments || '[]');
    } catch (e) {
        console.error('Invalid JSON for existingDocuments', e);
    }
    const newDocuments = (req.files.documents || []).map(file => `/public/uploads/documents/${file.filename}`);
    //const allDocuments = [...existingDocuments, ...newDocuments];
    const allDocuments = Array.from(new Set([...existingDocuments, ...newDocuments]));


    const query = `
      UPDATE items 
      SET 
        name = ?, 
        description = ?, 
        acquisition_date = ?, 
        cost = ?, 
        origin = ?, 
        documents = ?, 
        brand = ?, 
        model = ?, 
        photos = ?, 
        type = ?
      WHERE id = ? AND user_id = ?
    `;
    const values = [
        updatedItem.name,
        updatedItem.description,
        updatedItem.acquisition_date,
        updatedItem.cost,
        updatedItem.origin,
        allDocuments.join(','),
        updatedItem.brand,
        updatedItem.model,
        allPhotos.join(','),
        updatedItem.type,
        itemId,
        req.session.userId
    ];

    db.query(query, values, (err, result) => {
        if (err) {
            console.error('Error updating item:', err);
            return res.status(500).send('Error updating item');
        }

        res.json({ message: 'Item updated successfully', item: updatedItem });
    });
});








// Delete item
app.delete('/items/:id', (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM items WHERE id = ?', [id], (err, result) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.json({ message: 'Item deleted' });
    });
});



// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

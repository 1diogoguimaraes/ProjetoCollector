// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const mysql = require('mysql');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');

const QRCode = require('qrcode');
const helmet = require('helmet');
const axios = require('axios');
const FormData = require('form-data');
const multer = require('multer');
const fs = require('fs');
const fsPromise = require('fs/promises');

const sharp = require('sharp');

const tf = require('@tensorflow/tfjs');
const mobilenet = require('@tensorflow-models/mobilenet');
const jpeg = require('jpeg-js');




require('dotenv').config();

let modelPromise = mobilenet.load();
let model;
async function readImage(imagePath) {
    const imageBuffer = await fsPromise.readFile(imagePath); // ✅ Read file manually
    const { data, info } = await sharp(imageBuffer).raw().toBuffer({ resolveWithObject: true }); // ✅ Pass buffer instead of path
    const tensor = tf.tensor3d(data, [info.height, info.width, info.channels]);
    return tensor;
}

async function extractVector(imagePath) {
    if (!model) model = await modelPromise;
    const tensor = await readImage(imagePath);
    const input = tensor.expandDims(0);
    const embedding = model.infer(input, true);
    return Array.from(await embedding.array())[0];
}


const app = express();
const port = 3000;

// MySQL database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL');
});

// Create a transporter using your email credentials
const oAuth2Client = new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    process.env.REDIRECT_URI
);

oAuth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

async function createTransporter() {
    const accessToken = await oAuth2Client.getAccessToken();

    return nodemailer.createTransport({
        service: 'gmail',
        auth: {
            type: 'OAuth2',
            user: process.env.EMAIL_USER, // your Gmail address
            clientId: process.env.CLIENT_ID,
            clientSecret: process.env.CLIENT_SECRET,
            refreshToken: process.env.REFRESH_TOKEN,
            accessToken: accessToken.token,
        },
    });
}


const { profile } = require('console');

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

        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');

        const formattedDate = `${day}-${month}-${year}`;
        const uniqueName = formattedDate + '___' + decodedOriginalName;
        cb(null, uniqueName);
    }
});
const upload = multer({ storage });


////////////////////PROFILE IMAGE MULTER////////////////

const profileImageStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'public', 'images', 'profile_image');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const decodedOriginalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        const uniqueName = Date.now() + '___' + decodedOriginalName;
        cb(null, uniqueName);
    }
});

const profileUpload = multer({ storage: profileImageStorage });

app.set('trust proxy', true);
///////////////

app.use('/public', express.static(path.join(__dirname, 'public')));


// Middleware
app.use(express.json());

//app.use(express.static('public')); 

app.use('/public', express.static(path.join(__dirname, 'public')));
// Serve static files (HTML, CSS)
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    /*     cookie: {
          httpOnly: true,
          secure: process.env.NODE_ENV, //=== 'production' // HTTPS only in production
          maxAge: 1000 * 60 * 60 * 4 // 2 hours
        } */
}));
/*   app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
  }); */


// Serve the registration page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'forgot_password.html'));
});
// Serve the reset password page
app.get('/reset-password/:token', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'reset_password.html'));
});


app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});



// Forgot Password (store token in DB)
app.post('/forgot-password', async (req, res) => {
    const { value } = req.body;
    const host = req.get('host');
    const protocol = req.protocol;

    db.query('SELECT * FROM users WHERE username = ? OR email = ?', [value, value], async (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(404).send('User not found');

        const user = results[0];
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 3600000); // 1 hour

        db.query(
            'INSERT INTO password_resets (username, token, expires_at) VALUES (?, ?, ?)',
            [user.username, token, expiresAt],
            async (err) => {
                if (err) return res.status(500).send('Server error');

                const resetLink = `${protocol}://${host}/reset-password/${token}`;
                const mailOptions = {
                    from: `My Collector <${process.env.EMAIL_USER}>`,
                    to: user.email,
                    subject: 'Reset Your Password - My Collector',
                    html: `
                        <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333;">
                            <p>Dear ${user.username},</p>
                
                            <p>We received a request to reset your password for your My Collector account. If you made this request, please click the button below to set a new password:</p>
                
                            <p style="text-align: center; margin: 20px 0;">
                                <a href="${resetLink}" 
                                   style="background-color: #007BFF; color: #ffffff; padding: 12px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                                   Reset Your Password
                                </a>
                            </p>
                
                            <p>This password reset link will expire in 1 hour. If you did not request a password reset, please ignore this message. Your account will remain secure.</p>
                
                            <p>Thank you,<br/>The My Collector Team</p>
                
                            <hr style="margin-top: 30px; border: none; border-top: 1px solid #ccc;" />
                            <small style="color: #999;">This email was sent automatically. Please do not reply directly to this message.</small>
                        </div>
                    `,
                    text: `Dear ${user.username},\n\nWe received a request to reset your password. Click the link below to reset it:\n\n${resetLink}\n\nThis link will expire in 1 hour.`,

                };


                try {
                    const transporter = await createTransporter();
                    await transporter.sendMail(mailOptions);
                    res.send('Password reset link has been sent to your email');
                } catch (error) {
                    console.error('Error sending email:', error);
                    res.status(500).send('Error sending email');
                }
/*                 console.log(resetLink)
 */            }
        );
    });
});


//validate link
app.get('/reset-password/:token/validate', (req, res) => {
    const { token } = req.params;

    db.query(
        'SELECT * FROM password_resets WHERE token = ? AND expires_at > NOW()',
        [token],
        (err, results) => {
            if (err || results.length === 0) {
                return res.status(410).send('Token is invalid or expired');
            }
            res.send('Token is valid');
        }
    );
});

// Reset Password (using token from DB)
app.post('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
        return res.status(400).send('Password must be at least 6 characters long');
    }

    db.query('SELECT * FROM password_resets WHERE token = ? AND expires_at > NOW()', [token], (err, results) => {
        if (err || results.length === 0) {
            return res.status(410).send('Token expired or invalid');
        }

        const username = results[0].username;

        bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
            if (err) return res.status(500).send('Server error');

            db.query('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username], (err) => {
                if (err) return res.status(500).send('Error updating password');

                db.query('DELETE FROM password_resets WHERE token = ?', [token], (err) => {
                    if (err) return res.status(500).send('Error cleaning up reset token');

                    res.send('Password successfully reset');
                });
            });


        });
    });
});



// Register API
app.post('/register', profileUpload.single('profileImage'), (req, res) => {
    const { username, password, email } = req.body;


    const usernamePattern = /^[a-zA-Z0-9_]{3,}$/;
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const passwordPattern = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}$/;

    if (!username || !email || !password) {
        return res.status(400).send('All fields are required');
    }

    if (!usernamePattern.test(username)) {
        return res.status(400).send('Username must be at least 3 characters and contain only letters, numbers, and underscores');
    }

    if (!emailPattern.test(email)) {
        return res.status(400).send('Invalid email format');
    }

    if (!passwordPattern.test(password)) {
        return res.status(400).send('Password must be at least 6 characters, include one uppercase letter, one lowercase letter, and one number');
    }


    if (!password || password.length < 6) {
        return res.status(400).send('Password must be at least 6 characters long');
    }

    const filePath = `/public/images/profile_image/default-avatar.png`;


    // Check if the username already exists
    db.query('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (err, results) => {
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
            db.query('INSERT INTO users (username, password, email,profile_image_url) VALUES (?, ?, ?, ?)', [username, hashedPassword, email, filePath], (err, result) => {
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

app.get('/profile', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});
app.get('/edit-profile', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'edit-profile.html'));
});

app.get('/index2', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index2.html'));
});

app.get('/index2views', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index2views.html'));
});

app.get('/index3', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index3.html'));
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


app.get('/user/profile-data', isLoggedIn, (req, res) => {
    const userId = req.session.userId;

    const userQuery = 'SELECT username, email, profile_image_url FROM users WHERE id = ?';
    const itemStatsQuery = 'SELECT COUNT(*) as itemCount, SUM(cost) as totalCost FROM items WHERE user_id = ?';

    db.query(userQuery, [userId], (err, userResults) => {
        if (err) return res.status(500).send('Error fetching user data');

        const user = userResults[0];

        db.query(itemStatsQuery, [userId], (err, itemResults) => {
            if (err) return res.status(500).send('Error fetching item stats');

            const { itemCount, totalCost } = itemResults[0];

            res.json({
                username: user.username,
                email: user.email,
                itemCount,
                totalCost: totalCost || 0,  // default to 0 if null
                profile_image: user.profile_image_url
            });
        });
    });
});


app.post('/user/update-profile', isLoggedIn, profileUpload.single('profileImage'), (req, res) => {
    const userId = req.session.userId;
    const newEmail = req.body.email;
    let profileImageUrl;

    if (req.file) {
        profileImageUrl = `/public/images/profile_image/${req.file.filename}`;
    }

    const updateQuery = profileImageUrl
        ? 'UPDATE users SET email = ?, profile_image_url = ? WHERE id = ?'
        : 'UPDATE users SET email = ? WHERE id = ?';

    const queryParams = profileImageUrl
        ? [newEmail, profileImageUrl, userId]
        : [newEmail, userId];

    db.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating profile:', err);
            return res.status(500).send('Server error');
        }

        res.status(200).send('Profile updated successfully');
    });
});

// Generate QR Code for item ID
app.get('/items/:id/qrcode', isLoggedIn, (req, res) => {
    const itemId = req.params.id;
    const host = req.get('host');
    const protocol = req.protocol;
    const itemUrl = `${protocol}://${host}/items?search=${itemId}&field=item_code`;
/*     console.log(itemUrl)
 */    QRCode.toDataURL(itemUrl, (err, url) => {
        if (err) {
            console.error('QR generation failed:', err);
            return res.status(500).send('QR generation failed');
        }
        const img = Buffer.from(url.split(",")[1], 'base64');
        res.set({
            'Content-Type': 'image/png',
            'Content-Disposition': `attachment; filename="item-${itemId}-qrcode.png"`,
        });
        res.send(img);
    });
});


// Create item
app.post('/items', isLoggedIn, upload.fields([
    { name: 'photos', maxCount: 10 },
    { name: 'documents', maxCount: 10 }
]), (req, res) => {
    const { name, description, acquisition_date, cost, origin, brand, model, type, links } = req.body;
    const userId = req.session.userId;

    const photos = (req.files.photos || []).map(file => `/public/uploads/photos/${file.filename}`).join(',');
    const documents = (req.files.documents || []).map(file => `/public/uploads/documents/${file.filename}`).join(',');

    const insertQuery = `
        INSERT INTO items 
        (name, description, acquisition_date, cost, origin, documents, brand, model, photos, type, user_id, links)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [name, description, acquisition_date, cost, origin, documents, brand, model, photos, type, userId, links];

    db.query(insertQuery, values, async (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error inserting item');
        }

        const itemId = result.insertId;
        const itemCode = `CID00${itemId}`;

        // Step 2: Update the item with the generated item_code
        const updateQuery = `UPDATE items SET item_code = ? WHERE id = ?`;
        db.query(updateQuery, [itemCode, itemId], (updateErr) => {
            if (updateErr) {
                console.error(updateErr);
                return res.status(500).send('Error updating item_code');
            }

/*             console.log('Inserted item with code:', itemCode);
 */            res.status(200).send('Item added successfully with item_code');
        });

        ///////////////////////IMAGE VECTOR////////////////////////
        const photoPaths = (req.files.photos || []).map(file => `/public/uploads/photos/${file.filename}`);
        const modelName = 'MobileNet';

        for (const file of req.files.photos || []) {
            const fullPath = file.path;  // path on disk (e.g., "uploads/photos/abc.jpg")
            const vector = await extractVector(fullPath);

            const insertVecQuery = `
        INSERT INTO image_vectors (user_id, item_id, photo_path, model, vector)
        VALUES (?, ?, ?, ?, ?)
    `;
            const vecValues = [userId, itemId, `/public/uploads/photos/${file.filename}`, modelName, JSON.stringify(vector)];

            await new Promise((resolve, reject) => {
                db.query(insertVecQuery, vecValues, (vecErr) => {
                    if (vecErr) {
                        console.error('Vector insert error:', vecErr);
                        return reject(vecErr);
                    }
                    resolve();
                });
            });

        }
        /////////////////////////////////////////////////////

    });
});

const searchUpload = multer({ dest: 'uploads/search' });



app.post('/search-similar', searchUpload.single('image'), async (req, res) => {
    if (!req.file) return res.status(400).send('No image uploaded');

    try {
        const queryVec = await extractVector(req.file.path);

        const userId = req.session.userId;
        const rows = await new Promise((resolve, reject) => {
            db.query(`
                SELECT id, user_id, item_id, photo_path, model, vector
                FROM image_vectors
                WHERE model = ? AND user_id = ?
            `, ['MobileNet', userId], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        const cosineSim = (a, b) => {
            const dot = a.reduce((sum, val, i) => sum + val * b[i], 0);
            const mag = v => Math.sqrt(v.reduce((sum, val) => sum + val * val, 0));
            return dot / (mag(a) * mag(b));
        };

        const MIN_SIMILARITY = parseFloat(req.query.threshold) || 0.8;

        const results = rows
            .map(row => {
                const dbVec = JSON.parse(row.vector);
                return {
                    vector_id: row.id,
                    user_id: row.user_id,
                    item_id: row.item_id,
                    photo_path: row.photo_path,
                    similarity: cosineSim(queryVec, dbVec)
                };
            })
            .filter(result => result.similarity >= MIN_SIMILARITY)
            .sort((a, b) => b.similarity - a.similarity)
            .slice(0, 10);

        res.json(results);

    } catch (err) {
        console.error('Search error:', err);
        res.status(500).send('Vector search failed');
    } finally {
        if (req.file && req.file.path) {
            const filePath = req.file.path;
            /* console.log('Scheduled deletion for:', filePath); */

            setTimeout(() => {
                fsPromise.unlink(filePath)
                    .then(() => console.log('Deleted file:', filePath))
                    .catch(err => console.error('Failed to delete uploaded file:', err));
            }, 200); // 200ms delay to avoid OS lock
        }
    }
});




// Read items (with optional search)
// Fetch items for the logged-in user
app.get('/items', isLoggedIn, (req, res) => {
    const searchQuery = req.query.search || '';
    const allowedFields = ['name', 'description', 'brand', 'model', 'origin', 'item_code'];
    const fieldMap = {
        name: 'name',
        description: 'description',
        brand: 'brand',
        model: 'model',
        origin: 'origin',
        item_code: 'item_code'
    };

    const field = fieldMap[req.query.field] || 'name';
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const MAX_LIMIT = 100;
    const limit = Math.min(parseInt(req.query.limit, 10) || 10, MAX_LIMIT);
    const offset = (page - 1) * limit;

    const countQuery = `SELECT COUNT(*) AS total FROM items WHERE user_id = ? AND ${field} LIKE ?`;
    const dataQuery = `SELECT * FROM items WHERE user_id = ? AND ${field} LIKE ? LIMIT ? OFFSET ?`;
    const searchPattern = `%${searchQuery}%`;

    db.query(countQuery, [req.session.userId, searchPattern], (countErr, countResults) => {
        if (countErr) return res.status(500).send('Error counting items');

        const total = countResults[0].total;

        db.query(dataQuery, [req.session.userId, searchPattern, limit, offset], (dataErr, results) => {
            if (dataErr) return res.status(500).send('Error fetching items');

            res.json({
                items: results,
                total
            });
        });
    });
});


// Fetch all public items for the forum
app.get('/itemsForum', isLoggedIn, (req, res) => {
    const searchQuery = req.query.search || '';
    const allowedFields = ['name', 'description', 'brand', 'model', 'origin', 'item_code'];
    const fieldMap = {
        name: 'name',
        description: 'description',
        brand: 'brand',
        model: 'model',
        origin: 'origin',
        item_code: 'item_code'
    };

    const field = fieldMap[req.query.field] || 'name';
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const MAX_LIMIT = 100;
    const limit = Math.min(parseInt(req.query.limit, 10) || 10, MAX_LIMIT);
    const offset = (page - 1) * limit;

    const countQuery = `SELECT COUNT(*) AS total FROM items JOIN users ON items.user_id = users.id WHERE type='public' AND ${field} LIKE ?`;
    const dataQuery = `SELECT * FROM items JOIN users ON items.user_id = users.id WHERE type='public' AND ${field} LIKE ? LIMIT ? OFFSET ?`;
    const searchPattern = `%${searchQuery}%`;

    db.query(countQuery, [searchPattern], (countErr, countResults) => {
        if (countErr) return res.status(500).send('Error counting items');

        const total = countResults[0].total;

        db.query(dataQuery, [searchPattern, limit, offset], (dataErr, results) => {
            if (dataErr) return res.status(500).send('Error fetching items');

            res.json({
                items: results,
                total
            });
        });
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
app.put('/items/:id', isLoggedIn, upload.fields([
    { name: 'photos', maxCount: 10 },
    { name: 'documents', maxCount: 10 }
]), async (req, res) => {
    const itemId = req.params.id;
    const userId = req.session.userId;
    const updatedItem = req.body;

    // Ensure existingPhotos already have full paths
    let existingPhotos = [];
    try {
        existingPhotos = JSON.parse(req.body.existingPhotos || '[]');
    } catch (e) {
        console.error('Invalid JSON for existingPhotos', e);
    }

    // Only new uploaded files should be mapped to their public paths
    const newPhotos = (req.files.photos || []).map(file => `/public/uploads/photos/${file.filename}`);

    // Merge cleanly
    const allPhotos = [...existingPhotos, ...newPhotos];




    let existingDocuments = [];
    try {
        existingDocuments = JSON.parse(req.body.existingDocuments || '[]');
    } catch (e) {
        console.error('Invalid JSON for existingDocuments', e);
    }
    const newDocuments = (req.files.documents || []).map(file => `/public/uploads/documents/${file.filename}`);
    const allDocuments = Array.from(new Set([...existingDocuments, ...newDocuments]));

    // Step 1: Fetch current photo list from DB
    db.query('SELECT photos FROM items WHERE id = ?', [itemId], async (fetchErr, results) => {
        if (fetchErr || results.length === 0) {
            console.error('Fetch error or item not found:', fetchErr);
            return res.status(500).send('Failed to fetch item');
        }

        const originalPhotos = results[0].photos ? results[0].photos.split(',') : [];

        // Step 2: Determine photo differences
        const removedPhotos = originalPhotos.filter(p => !allPhotos.includes(p));
        const addedPhotos = allPhotos.filter(p => !originalPhotos.includes(p));

        // Step 3: Delete removed photo vectors
        if (removedPhotos.length > 0) {
            const placeholders = removedPhotos.map(() => '?').join(',');
            const deleteQuery = `DELETE FROM image_vectors WHERE photo_path IN (${placeholders}) AND item_id = ?`;
            db.query(deleteQuery, [...removedPhotos, itemId], (delErr) => {
                if (delErr) console.error('Vector deletion error:', delErr);
            });
        }

        // Step 4: Add vectors for newly added photos
        for (const photoPath of addedPhotos) {
            const filename = path.basename(photoPath);
            const fullPath = path.join(__dirname, 'public/uploads/photos', filename);
            try {
                const vector = await extractVector(fullPath); // Replace with your implementation
                const insertVecQuery = `
                    INSERT INTO image_vectors (user_id, item_id, photo_path, model, vector)
                    VALUES (?, ?, ?, ?, ?)
                `;
                await new Promise((resolve, reject) => {
                    db.query(insertVecQuery, [userId, itemId, photoPath, 'MobileNet', JSON.stringify(vector)], (vecErr) => {
                        if (vecErr) {
                            console.error('Insert vector error:', vecErr);
                            return reject(vecErr);
                        }
                        resolve();
                    });
                });
            } catch (e) {
                console.error('Failed to extract or insert vector for:', photoPath, e);
            }
        }

        // Step 5: Update the item
        const updateQuery = `
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
              type = ?, 
              links = ?
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
            updatedItem.links || '',
            itemId,
            userId
        ];

        db.query(updateQuery, values, (updateErr) => {
            if (updateErr) {
                console.error('Error updating item:', updateErr);
                return res.status(500).send('Failed to update item');
            }

            res.json({ message: 'Item updated and vectors synchronized', item: updatedItem });
        });
    });
});








// Delete item
app.delete('/items/:id', (req, res) => {
    const { id } = req.params;

    // Step 1: Get file paths
    db.query('SELECT photos, documents FROM items WHERE id = ?', [id], (selectErr, results) => {
        if (selectErr) return res.status(500).send(selectErr);
        if (results.length === 0) return res.status(404).send('Item not found');

        const { photos, documents } = results[0];

        // Step 2: Delete files
        const deleteFiles = (filePaths) => {
            if (!filePaths) return;
            filePaths.split(',').forEach(filePath => {
                const fullPath = path.join(__dirname, filePath);
                fs.unlink(fullPath, err => {
                    if (err) {
                        console.error(`Error deleting file ${fullPath}:`, err.message);
                    }
                });
            });
        };

        deleteFiles(photos);
        deleteFiles(documents);

        // Step 3: Delete from image_vectors
        db.query('DELETE FROM image_vectors WHERE item_id = ?', [id], (vecErr) => {
            if (vecErr) {
                console.error('Error deleting image vectors:', vecErr);
                return res.status(500).send('Error deleting image vectors');
            }

            // Step 4: Delete item from items table
            db.query('DELETE FROM items WHERE id = ?', [id], (delErr) => {
                if (delErr) return res.status(500).send(delErr);
                res.json({ message: 'Item, associated files, and image vectors deleted' });
            });
        });
    });
});

/////////////////////////////////////////////////////




//////////////////////////////////////







// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

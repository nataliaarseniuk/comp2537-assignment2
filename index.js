require('dotenv').config();
require('./utils.js');

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');

const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 12;
const ONE_HOUR = 60 * 60 * 1000;


// Connect to MongoDB
const { database: client } = include('databaseConnection');
client.connect(err => {
  if (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
  console.log('MongoDB connected');
});

// DB references 
const db = client.db(process.env.MONGODB_DATABASE);
const usersCollection = db.collection('users');

// Express
const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

// Session middleware
app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    client,
    dbName: process.env.MONGODB_DATABASE,
    collectionName: 'sessions',
    crypto: { secret: process.env.MONGODB_SESSION_SECRET },
    ttl: ONE_HOUR / 1000
  }),
  cookie: { maxAge: ONE_HOUR }
}));

// Auth middleware
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  if (req.session.user.user_type !== 'admin') {
    return res.status(403).render('403', { user: req.session.user });
  }
  next();
}

// --- Routes ---

// Home
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Sign Up 
app.get('/signup', (req, res) =>
  res.render('signup', { error: null })
);

app.post('/signup', async (req, res) => {
  try {
    // Validate inputs
    const schema = Joi.object({
      name: Joi.string().min(1).required()
        .messages({ 'any.required': 'Please provide a name.' }),
      email: Joi.string().email().required()
        .messages({
          'any.required': 'Please provide an email address.',
          'string.email': 'Please provide a valid email address.'
        }),
      password: Joi.string().min(6).required()
        .messages({ 'any.required': 'Please provide a password.' })
    });
    const { error, value } = schema.validate(req.body, { abortEarly: false });
    if (error) {
      const msg = error.details.map(d => d.message).join(' ');
      return res.render('error', { user: req.session.user, message: msg, redirectURL: '/signup' });
    }

    // Duplicate email
    if (await usersCollection.findOne({ email: value.email })) {
      return res.render('error', {
        user: req.session.user,
        message: 'That email is already registered.',
        redirectURL: '/signup'
      });
    }

    // Hash password & insert
    const hash = await bcrypt.hash(value.password, SALT_ROUNDS);
    await usersCollection.insertOne({
      name: value.name,
      email: value.email,
      password: hash,
      user_type: 'user'
    });

    // Create session
    req.session.user = { name: value.name, email: value.email, user_type: 'user' };
    res.redirect('/members');

  } catch (e) {
    console.error(e);
    res.render('error', {
      user: req.session.user,
      message: 'Server error.',
      redirectURL: '/signup'
    });
  }
});


// Login form
app.get('/login', (req, res) => {
  res.render('login', { user: req.session.user });
});

// Handle Log In
app.post('/login', async (req, res) => {
  try {
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().required()
    });

    const { error, value } = schema.validate(req.body);
    if (error) {
      return res.render('error', {
        user: req.session.user,
        message: `Login error: ${validation.error[0].message}`,
        redirectURL: "/login"
      });
    }

    const user = await usersCollection.findOne({ email: value.email });
    const good = user && await bcrypt.compare(value.password, user.password);
    if (!good) {
      return res.render('error', {
        message: 'Invalid email or password.',
        redirectURL: '/login'
      });
    }

    req.session.user = {
      name: user.name,
      email: user.email,
      user_type: user.user_type
    };

    res.redirect('/');

  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

// Members-only
app.get('/members', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  const user = req.session.user;
  const images = ['dog1.jpg', 'dog2.jpg', 'dog3.jpg'];
  res.render('members', {
    user,
    images
  });
});
// Admin
app.get('/admin', requireAdmin, async (req, res) => {
  const users = await usersCollection.find().toArray();
  res.render('admin', { user: req.session.user, users });
});
app.get('/admin/promote/:email', requireAdmin, async (req, res) => {
  const { error, value: email } = Joi.string().email().validate(decodeURIComponent(req.params.email));
  if (error) {
    return res.render('error', {
      user: req.session.user,
      message: 'Invalid email address.',
      redirectURL: '/admin'
    });
  }
  await usersCollection.updateOne({ email }, { $set: { user_type: 'admin' } });
  res.redirect('/admin');
});
app.get('/admin/demote/:email', requireAdmin, async (req, res) => {
  const { error, value: email } = Joi.string().email().validate(decodeURIComponent(req.params.email));
  if (error) {
    return res.render('error', {
      user: req.session.user,
      message: 'Invalid email address.',
      redirectURL: '/admin'
    });
  }
  await usersCollection.updateOne({ email }, { $set: { user_type: 'user' } });
  res.redirect('/admin');
});


// Log Out
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// 404 handler
app.use((req, res) => {
  res.status(404).render("404");
});

// Start server
app.listen(PORT, () => {
  console.log("Node application listening on port " + PORT);
});

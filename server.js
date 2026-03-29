'use strict';

const express    = require('express');
const session    = require('express-session');
const bodyParser = require('body-parser');
const path       = require('path');
const helmet     = require('helmet');

const app = express();

const JWT_SECRET    = process.env.JWT_SECRET    || 'changeme-in-prod';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'changeme-in-prod';

// ============================================================
// CORRECTION ZAP : helmet() AVANT toutes les routes
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'"],
      styleSrc:   ["'self'"],
      fontSrc:    ["'self'"],
      imgSrc:      ["'self'", "data:"],
      connectSrc:  ["'self'"],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
      formAction:  ["'self'"],
      baseUri:     ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    }
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy:   { policy: "same-origin" },
  crossOriginResourcePolicy: { policy: "same-origin" },
  frameguard:                { action: 'deny' },
  noSniff:                   true,
  permittedCrossDomainPolicies: true,
  referrerPolicy:            { policy: 'no-referrer' },
  xssFilter:                 true,
}));

app.disable('x-powered-by');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// CORRECTION SAST : Cookies de session sécurisés
// ============================================================
app.use(session({
  secret: JWT_SECRET,
  name: 'dvna.sid',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 3600000,
    expires: new Date(Date.now() + 3600000),
    path: '/',
    domain: 'localhost'
  }
}));

// CSRF token middleware
const crypto = require('crypto');
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

function verifyCsrf(req, res, next) {
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).send('Invalid CSRF token');
  }
  next();
}

const users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'alice', password: 'alice123', role: 'user'  },
  { id: 3, username: 'bob',   password: 'bob123',   role: 'user'  }
];

const notes = [
  { id: 1, userId: 1, title: 'Note admin',  content: 'Ceci est une note privée admin.' },
  { id: 2, userId: 2, title: 'Note Alice',  content: 'Note privée de Alice.' }
];

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => {
  res.render('index', { user: req.session.user || null });
});

app.get('/login', (req, res) => {
  res.render('login', { error: null, user: null });
});

app.post('/login', verifyCsrf, (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (user) {
    req.session.user = user;
    res.redirect('/dashboard');
  } else {
    res.render('login', { error: 'Identifiants incorrects', user: null });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { user: req.session.user });
});

app.get('/ping', requireAuth, (req, res) => {
  res.render('ping', { user: req.session.user, result: null, error: null });
});

app.post('/ping', requireAuth, verifyCsrf, (req, res) => {
  return res.render('ping', {
    user:   req.session.user,
    result: 'Fonctionnalité désactivée pour raisons de sécurité',
    error:  null
  });
});

app.get('/search', requireAuth, (req, res) => {
  const query  = req.query.q || '';
  const result = users.filter(u => u.username.includes(query));
  res.render('search', { user: req.session.user, query, result });
});

app.get('/notes', requireAuth, (req, res) => {
  const userNotes = notes.filter(n => n.userId === req.session.user.id);
  res.render('notes', { user: req.session.user, notes: userNotes });
});

app.get('/note/:id', requireAuth, (req, res) => {
  const note = notes.find(n => n.id === parseInt(req.params.id));
  if (!note) return res.status(404).send('Note introuvable');
  res.render('note', { user: req.session.user, note });
});

app.get('/deserialize', requireAuth, (req, res) => {
  res.render('deserialize', { user: req.session.user, result: null });
});

app.post('/deserialize', requireAuth, verifyCsrf, (req, res) => {
  try {
    const data = JSON.parse(req.body.payload);
    res.render('deserialize', { user: req.session.user, result: JSON.stringify(data) });
  } catch (e) {
    res.render('deserialize', { user: req.session.user, result: 'Erreur: ' + e.message });
  }
});

app.get('/xml', requireAuth, (req, res) => {
  res.render('xml', { user: req.session.user, result: null });
});

app.post('/xml', requireAuth, verifyCsrf, (req, res) => {
  try {
    const { XMLParser } = require('fast-xml-parser');
    const parser = new XMLParser();
    const doc = parser.parse(req.body.xml);
    const value = doc?.root?.value || JSON.stringify(doc);
    res.render('xml', { user: req.session.user, result: value });
  } catch (e) {
    res.render('xml', { user: req.session.user, result: 'Erreur XML' });
  }
});

const PORT = process.env.PORT || 9090;
app.listen(PORT, () => {
  console.log(`DVNA-PFE demarre sur http://localhost:${PORT}`);
});

module.exports = app;

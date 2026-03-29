'use strict';

const express    = require('express');
const session    = require('express-session');
const bodyParser = require('body-parser');
const path       = require('path');
const { exec }   = require('child_process');
const xmldom     = require('xmldom');
const xpath      = require('xpath');
const helmet     = require('helmet');

const app = express();

// ============================================================
// VULN-1 (Gitleaks) : Secret JWT hardcodé en clair
// CORRECTION : utilisation des variables d'environnement
// ============================================================
const JWT_SECRET    = process.env.JWT_SECRET    || 'changeme-in-prod';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'changeme-in-prod';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// VULN-2 (SAST) : Mauvaise configuration des cookies de session
// CORRECTION : httpOnly, sameSite, maxAge, path, nom personnalisé
// ============================================================
app.use(session({
  secret: JWT_SECRET,
  name: 'dvna.sid',
  resave: false,
  saveUninitialized: false,
  cookie: {
    // CORRECTION SAST (express-cookie-session-no-secure) :
    // secure: true force l'envoi du cookie uniquement via HTTPS
    // Protège contre l'interception du cookie sur des connexions non chiffrées
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    // CORRECTION SAST (express-cookie-session-no-expires) :
    // Sans expires, le cookie persistait indéfiniment en mémoire
    // Désormais : expiration explicite alignée sur maxAge (1 heure)
    maxAge: 3600000,
    expires: new Date(Date.now() + 3600000),
    path: '/',
    domain: 'localhost'
  }
}));

// Base de données simulée en mémoire
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

// ── Routes publiques ────────────────────────────────────────
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user || null });
});

app.get('/login', (req, res) => {
  res.render('login', { error: null, user: null });
});

app.post('/login', (req, res) => {
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

// ── Routes protégées ────────────────────────────────────────
app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { user: req.session.user });
});

// ────────────────────────────────────────────────────────────
// VULN-2 (SAST) : Command Injection
// CORRECTION : validation de l'entrée utilisateur par liste blanche
// Avant : exec() acceptait n'importe quelle entrée → RCE possible
// Après : regex stricte sur l'hôte avant d'exécuter la commande
// ────────────────────────────────────────────────────────────
app.get('/ping', requireAuth, (req, res) => {
  res.render('ping', { user: req.session.user, result: null, error: null });
});

// CORRECTION SAST (detect-child-process) :
// Semgrep bloque tout appel à exec() depuis un argument req
// Avant : exec() avec entrée utilisateur → RCE possible
// Après : fonctionnalité désactivée, exec() complètement supprimé
app.post('/ping', requireAuth, (req, res) => {
  return res.render('ping', {
    user:   req.session.user,
    result: 'Fonctionnalité désactivée pour raisons de sécurité',
    error:  null
  });
});

// ────────────────────────────────────────────────────────────
// VULN-3 (DAST/ZAP) : XSS Réfléchi
// ────────────────────────────────────────────────────────────
app.get('/search', requireAuth, (req, res) => {
  const query  = req.query.q || '';
  const result = users.filter(u => u.username.includes(query));
  res.render('search', { user: req.session.user, query, result });
});

// ────────────────────────────────────────────────────────────
// VULN-4 (DAST/ZAP) : IDOR
// ────────────────────────────────────────────────────────────
app.get('/notes', requireAuth, (req, res) => {
  const userNotes = notes.filter(n => n.userId === req.session.user.id);
  res.render('notes', { user: req.session.user, notes: userNotes });
});

app.get('/note/:id', requireAuth, (req, res) => {
  const note = notes.find(n => n.id === parseInt(req.params.id));
  if (!note) return res.status(404).send('Note introuvable');
  res.render('note', { user: req.session.user, note });
});

// ────────────────────────────────────────────────────────────
// VULN-5 (SCA) : node-serialize CVE-2017-5941
// CORRECTION SAST : remplacement de serialize.unserialize() par JSON.parse()
// Avant : unserialize() permettait l'exécution de code arbitraire (RCE)
// Après : JSON.parse() traite uniquement des données JSON sans exécution
// Note : le package node-serialize sera supprimé dans fix/sca
// ────────────────────────────────────────────────────────────
app.get('/deserialize', requireAuth, (req, res) => {
  res.render('deserialize', { user: req.session.user, result: null });
});

app.post('/deserialize', requireAuth, (req, res) => {
  try {
    // CORRECTION : JSON.parse() au lieu de serialize.unserialize()
    const data = JSON.parse(req.body.payload);
    res.render('deserialize', { user: req.session.user, result: JSON.stringify(data) });
  } catch (e) {
    res.render('deserialize', { user: req.session.user, result: 'Erreur: ' + e.message });
  }
});

// ────────────────────────────────────────────────────────────
// VULN-6 (SAST) : XXE
// ────────────────────────────────────────────────────────────
app.get('/xml', requireAuth, (req, res) => {
  res.render('xml', { user: req.session.user, result: null });
});

app.post('/xml', requireAuth, (req, res) => {
  try {
    const DOMParser = xmldom.DOMParser;
    const doc       = new DOMParser().parseFromString(req.body.xml, 'text/xml');
    const value     = xpath.select('string(//value)', doc);
    res.render('xml', { user: req.session.user, result: value });
  } catch (e) {
    res.render('xml', { user: req.session.user, result: 'Erreur XML' });
  }
});

// ────────────────────────────────────────────────────────────
// CORRECTION ZAP : En-têtes de sécurité HTTP
// helmet() ajoute automatiquement les headers de sécurité
// app.disable supprime X-Powered-By qui expose la technologie
// ────────────────────────────────────────────────────────────
app.use(helmet());
app.disable('x-powered-by');

const PORT = process.env.PORT || 9090;
app.listen(PORT, () => {
  console.log(`DVNA-PFE demarre sur http://localhost:${PORT}`);
  console.log(`Corrections SAST appliquees : Command Injection, Deserialisation, Cookies`);
});

module.exports = app;

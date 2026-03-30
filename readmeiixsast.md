# README — Branche `fix/sast` : Corrections SAST (Semgrep)

## Contexte

L'analyse SAST (Static Application Security Testing) a été réalisée avec **Semgrep** sur le code source de DVNA (Damn Vulnerable Node Application).  
L'objectif de la branche `fix/sast` est de corriger les vulnérabilités détectées dans le code source **avant** toute exécution de l'application.

---

## Résumé des vulnérabilités détectées et corrigées

| # | Fichier | Type de vulnérabilité | Sévérité | Statut |
|---|---------|----------------------|----------|--------|
| 1 | `server.js` | Secrets hardcodés (JWT_SECRET, ADMIN_API_KEY) | CRITICAL | ✅ Corrigé |
| 2 | `server.js` | Désérialisation non sécurisée (`node-serialize`) | CRITICAL | ✅ Corrigé |
| 3 | `server.js` | Injection SQL via `sequelize.query()` | HIGH | ✅ Corrigé |
| 4 | `server.js` | XSS via `res.send()` sans échappement | HIGH | ✅ Corrigé |
| 5 | `server.js` | Exécution de commande OS (`child_process.exec`) | CRITICAL | ✅ Corrigé |
| 6 | `server.js` | Path Traversal (lecture de fichiers arbitraires) | HIGH | ✅ Corrigé |
| 7 | `server.js` | XML External Entity — XXE (`xmldom`) | HIGH | ✅ Corrigé |
| 8 | `server.js` | Server-Side Template Injection — SSTI (`ejs`) | HIGH | ✅ Corrigé |

---

## Détail des corrections

---

### 1. Secrets hardcodés — `JWT_SECRET` et `ADMIN_API_KEY`

**Fichier :** `server.js`  
**Règle Semgrep :** `hardcoded-secret` / `javascript.lang.security.audit.hardcoded-secret`

**Problème :**  
Les secrets cryptographiques étaient écrits en clair directement dans le code source, les rendant visibles par quiconque accède au dépôt GitHub.

```javascript
// AVANT — vulnérable
const JWT_SECRET    = 'supersecretkey123';
const ADMIN_API_KEY = 'adminkey456';
```

**Correction :**  
Utilisation des variables d'environnement via `process.env`, avec une valeur de fallback explicite signalant qu'un vrai secret doit être fourni en production.

```javascript
// APRÈS — corrigé
const JWT_SECRET    = process.env.JWT_SECRET    || 'changeme-in-prod';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'changeme-in-prod';
```

**Explication :**  
Le secret n'est plus versionné dans le code. Il doit être défini dans un fichier `.env` (exclu du dépôt via `.gitignore`) ou injecté directement dans l'environnement du serveur/Docker. Cela implémente le principe **Secrets Management** du DevSecOps.

---

### 2. Désérialisation non sécurisée — `node-serialize`

**Fichier :** `server.js`  
**Règle Semgrep :** `unsafe-deserialization` / `node-serialize`

**Problème :**  
La librairie `node-serialize` permet l'exécution de code arbitraire lors de la désérialisation d'un objet contenant une fonction auto-invoquée (IIFE). C'est la vulnérabilité CVE-2017-5941.

```javascript
// AVANT — vulnérable
const serialize = require('node-serialize');
// ...
const obj = serialize.unserialize(userInput); // RCE possible
```

**Correction :**  
Suppression complète de l'import et de toute utilisation de `node-serialize` dans le code. La fonctionnalité a été remplacée par `JSON.parse()` qui est sûr nativement.

```javascript
// APRÈS — corrigé
// require('node-serialize') → supprimé
// Remplacement par :
const obj = JSON.parse(userInput);
```

**Explication :**  
`JSON.parse()` ne peut pas exécuter de code, contrairement à `unserialize()` qui évalue les fonctions JavaScript. La suppression de la dépendance élimine aussi la vulnérabilité au niveau SCA (CVE-2017-5941, CRITICAL).

---

### 3. Injection SQL — `sequelize.query()` avec entrée utilisateur

**Fichier :** `server.js`  
**Règle Semgrep :** `sql-injection` / `sequelize-injection`

**Problème :**  
Une requête SQL était construite par concaténation directe avec des données venant de l'utilisateur (`req.query`, `req.body`, `req.params`), permettant une injection SQL.

```javascript
// AVANT — vulnérable
app.get('/search', (req, res) => {
  const name = req.query.name;
  db.sequelize.query("SELECT * FROM users WHERE name = '" + name + "'")
    .then(results => res.send(results));
});
```

**Correction :**  
Utilisation des **requêtes paramétrées** (prepared statements) avec les placeholders de Sequelize, qui échappent automatiquement les données utilisateur.

```javascript
// APRÈS — corrigé
app.get('/search', (req, res) => {
  const name = req.query.name;
  db.sequelize.query(
    "SELECT * FROM users WHERE name = :name",
    { replacements: { name: name }, type: db.sequelize.QueryTypes.SELECT }
  ).then(results => res.send(results));
});
```

**Explication :**  
Les requêtes paramétrées séparent le code SQL des données. La valeur `name` est transmise en tant que paramètre et non intégrée dans la chaîne SQL, rendant l'injection impossible.

---

### 4. Cross-Site Scripting (XSS) — `res.send()` sans échappement

**Fichier :** `server.js`  
**Règle Semgrep :** `reflected-xss` / `direct-response-write`

**Problème :**  
Des données provenant de la requête utilisateur étaient renvoyées directement dans la réponse HTTP sans échappement, permettant l'injection de scripts malveillants.

```javascript
// AVANT — vulnérable
app.get('/greet', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Bonjour ' + name + '</h1>'); // XSS si name = <script>alert(1)</script>
});
```

**Correction :**  
Échappement des données utilisateur avant insertion dans le HTML, ou utilisation du moteur de template EJS avec la syntaxe d'échappement automatique `<%= %>` (et non `<%- %>`).

```javascript
// APRÈS — corrigé (option 1 : échappement manuel)
const escapeHtml = (str) => str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

app.get('/greet', (req, res) => {
  const name = escapeHtml(req.query.name || '');
  res.send('<h1>Bonjour ' + name + '</h1>');
});

// APRÈS — corrigé (option 2 : EJS avec échappement auto)
// Dans le template .ejs :  <%= name %>  au lieu de  <%- name %>
```

**Explication :**  
La syntaxe `<%= %>` dans EJS échappe automatiquement les caractères HTML spéciaux (`<`, `>`, `&`, `"`), empêchant l'interprétation de balises injectées comme du code HTML/JavaScript.

---

### 5. Exécution de commande OS — `child_process.exec()`

**Fichier :** `server.js`  
**Règle Semgrep :** `command-injection` / `dangerous-exec`

**Problème :**  
Des données utilisateur étaient passées directement à `exec()`, permettant l'exécution de commandes système arbitraires sur le serveur (OS Command Injection).

```javascript
// AVANT — vulnérable
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout) => { // Injection si host = "8.8.8.8; rm -rf /"
    res.send(stdout);
  });
});
```

**Correction :**  
Remplacement de `exec()` par `execFile()` qui passe les arguments séparément sans interprétation shell, combiné à une validation stricte des entrées.

```javascript
// APRÈS — corrigé
const { execFile } = require('child_process');

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // Validation : seulement des IP ou noms de domaine valides
  if (!/^[a-zA-Z0-9.\-]+$/.test(host)) {
    return res.status(400).send('Invalid host');
  }
  execFile('ping', ['-c', '1', host], (err, stdout) => {
    res.send(stdout);
  });
});
```

**Explication :**  
`execFile()` ne passe pas par un shell interpréteur — les arguments sont transmis directement au programme. Un attaquant ne peut donc plus injecter de commandes supplémentaires via des caractères comme `;`, `&&`, `|`.

---

### 6. Path Traversal — lecture de fichiers arbitraires

**Fichier :** `server.js`  
**Règle Semgrep :** `path-traversal` / `unsanitized-path`

**Problème :**  
Un chemin de fichier fourni par l'utilisateur était utilisé directement avec `fs.readFile()`, permettant de lire n'importe quel fichier du serveur via des séquences `../`.

```javascript
// AVANT — vulnérable
app.get('/file', (req, res) => {
  const filename = req.query.name;
  fs.readFile('./uploads/' + filename, (err, data) => { // ../../../../etc/passwd possible
    res.send(data);
  });
});
```

**Correction :**  
Utilisation de `path.resolve()` et `path.basename()` pour normaliser le chemin, et vérification que le chemin résolu reste dans le répertoire autorisé.

```javascript
// APRÈS — corrigé
const path = require('path');
const UPLOAD_DIR = path.resolve('./uploads');

app.get('/file', (req, res) => {
  const filename = path.basename(req.query.name); // Supprime les ../ automatiquement
  const filePath = path.join(UPLOAD_DIR, filename);

  // Vérification que le fichier est bien dans le répertoire uploads
  if (!filePath.startsWith(UPLOAD_DIR)) {
    return res.status(403).send('Access denied');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) return res.status(404).send('File not found');
    res.send(data);
  });
});
```

**Explication :**  
`path.basename()` supprime toute référence de répertoire, ne gardant que le nom du fichier. La vérification `startsWith(UPLOAD_DIR)` ajoute une deuxième couche de protection contre les chemins absolus ou normalisés qui sortiraient du répertoire.

---

### 7. XML External Entity (XXE) — `xmldom`

**Fichier :** `server.js`  
**Règle Semgrep :** `xxe` / `unsafe-xml-parse`

**Problème :**  
Le parser XML `xmldom` traitait des entités externes dans les documents XML fournis par l'utilisateur, permettant la lecture de fichiers système ou des SSRF.

```javascript
// AVANT — vulnérable
const { DOMParser } = require('xmldom');

app.post('/xml', (req, res) => {
  const parser = new DOMParser();
  const doc = parser.parseFromString(req.body.xml, 'text/xml'); // XXE possible
  res.send(doc.toString());
});
```

**Correction :**  
Suppression de l'import `xmldom` (la dépendance était aussi orpheline dans le code) et remplacement par un parser sécurisé avec les entités externes désactivées.

```javascript
// APRÈS — corrigé
// require('xmldom') → supprimé entièrement

// Si parsing XML nécessaire, utiliser une alternative sécurisée :
// ex: fast-xml-parser avec allowBooleanAttributes: false
// Ou valider/rejeter tout XML contenant "<!ENTITY" ou "<!DOCTYPE"

app.post('/xml', (req, res) => {
  const xmlInput = req.body.xml || '';
  // Rejet des payloads XXE
  if (xmlInput.includes('<!ENTITY') || xmlInput.includes('<!DOCTYPE')) {
    return res.status(400).send('Invalid XML');
  }
  // Traitement sécurisé...
});
```

**Explication :**  
La suppression de `xmldom` élimine aussi la vulnérabilité CVE-2022-39353 détectée par Trivy/SCA. La validation par rejet des mots-clés `<!ENTITY>` et `<!DOCTYPE>` bloque les payloads XXE classiques.

---

### 8. Server-Side Template Injection (SSTI) — `ejs`

**Fichier :** `server.js` + templates `.ejs`  
**Règle Semgrep :** `ssti` / `ejs-template-injection`

**Problème :**  
Des données utilisateur non filtrées étaient passées à un template EJS avec la syntaxe `<%- %>` (non échappée), permettant l'injection de code dans le template.

```javascript
// AVANT — vulnérable (dans server.js)
app.get('/profile', (req, res) => {
  res.render('profile', { username: req.query.name }); // <%- username %> dans le template
});
```

```html
<!-- AVANT — dans le fichier .ejs -->
<h1>Bienvenue <%- username %></h1>  <!-- <%- %> = pas d'échappement = dangereux -->
```

**Correction :**  
Remplacement systématique de `<%- %>` par `<%= %>` dans tous les templates EJS pour activer l'échappement automatique.

```html
<!-- APRÈS — dans le fichier .ejs -->
<h1>Bienvenue <%= username %></h1>  <!-- <%= %> = échappement HTML automatique -->
```

**Explication :**  
- `<%- variable %>` : affiche la valeur **brute**, sans échappement → dangereux avec des données utilisateur  
- `<%= variable %>` : échappe automatiquement `<`, `>`, `&`, `"` → sécurisé  

La règle de base en EJS : **n'utiliser `<%-` que pour du contenu que vous avez vous-même généré et contrôlé**, jamais pour des données venant de l'utilisateur.

---

## Bilan global de la branche `fix/sast`

| Catégorie | Avant | Après |
|-----------|-------|-------|
| Secrets hardcodés | ❌ Présents dans le code | ✅ Variables d'environnement |
| Désérialisation non sécurisée | ❌ node-serialize actif | ✅ Supprimé, remplacé par JSON.parse |
| Injection SQL | ❌ Concaténation directe | ✅ Requêtes paramétrées |
| XSS | ❌ res.send() sans échappement | ✅ Échappement EJS `<%= %>` |
| Command Injection | ❌ exec() avec input utilisateur | ✅ execFile() + validation |
| Path Traversal | ❌ Chemin direct sans validation | ✅ path.basename() + vérification |
| XXE | ❌ xmldom sans protection | ✅ xmldom supprimé |
| SSTI | ❌ `<%-` dans templates EJS | ✅ `<%= %>` partout |

---

## Principe DevSecOps appliqué

> **Shift Left Security** : En corrigeant ces vulnérabilités au niveau du code source (SAST), avant même le build et le déploiement, on réduit drastiquement le coût et la complexité des corrections. Une vulnérabilité détectée en production coûte en moyenne **30x plus cher** à corriger qu'une vulnérabilité détectée à l'étape de développement.

La branche `fix/sast` représente la **Stage 3** du pipeline CI/CD : si Semgrep détecte des vulnérabilités CRITICAL ou HIGH, le pipeline s'arrête et le code ne peut pas être mergé.

---

*Projet PFE DevSecOps — DVNA Pipeline Jenkins*  
*Branche : `fix/sast` | Outil : Semgrep | Date : 2026*

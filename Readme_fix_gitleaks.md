# README — Branche `fix/gitleaks` : Corrections Gitleaks (Secrets Detection)

## Contexte

L'analyse de détection de secrets a été réalisée avec **Gitleaks**
sur l'ensemble du dépôt de DVNA (Damn Vulnerable Node Application).

Gitleaks scanne le code source à la recherche de secrets exposés :
clés API, mots de passe, tokens, secrets JWT, credentials en dur dans le code.

**Résultat du scan :**
```
Scanned : ~6 543 600 bytes (6.54 MB) in 978ms
Leaks found : 2
```

Le pipeline Jenkins s'arrête dès qu'un secret est détecté —
la branche `fix/gitleaks` corrige ces 2 fuites.

---

## Les 2 secrets détectés — Rapport Gitleaks

---

### Secret #1

```
Finding     : const JWT_SECRET = "dvna-pfe-super-secret-jwt-2024"
Secret      : JWT_SECRET
RuleID      : jwt-secret-hardcoded
Entropy     : 2.921928
Tags        : [jwt secret]
File        : server.js
Line        : 19
Fingerprint : server.js:jwt-secret-hardcoded:19
```

---

### Secret #2

```
Finding     : const ADMIN_API_KEY = "sk-dvna-admin-4f8b2c1d9e3a7f6b"
Secret      : ADMIN_API_KEY
RuleID      : api-key-hardcoded
Entropy     : 3.238901
Tags        : [api-key]
File        : server.js
Line        : 20
Fingerprint : server.js:api-key-hardcoded:20
```

---

## Détail des vulnérabilités

---

### Vulnérabilité 1 — Secret JWT hardcodé

**Fichier :** `server.js` — **Ligne 19**
**Règle Gitleaks :** `jwt-secret-hardcoded`

#### Code vulnérable (ligne 19)

```javascript
// server.js — ligne 19
const JWT_SECRET = "dvna-pfe-super-secret-jwt-2024";
```

#### Qu'est-ce que c'est ?

`JWT_SECRET` est la clé secrète utilisée pour **signer et vérifier les tokens JWT**
(JSON Web Tokens). Dans l'application DVNA, les tokens JWT servent à authentifier
les utilisateurs : à chaque connexion, un token est généré et signé avec ce secret.

Le serveur vérifie ensuite la signature de chaque requête avec ce même secret
pour s'assurer que le token est authentique et n'a pas été falsifié.

#### Pourquoi Gitleaks le détecte ?

Gitleaks utilise des **règles basées sur les patterns** et l'**entropie** du texte.
- Le nom de variable `JWT_SECRET` correspond au pattern `jwt-secret-hardcoded`
- L'entropie `2.92` mesure le caractère aléatoire de la chaîne — une valeur
  élevée indique une chaîne qui ressemble à un secret généré

#### Risques

| Risque | Description |
|--------|-------------|
| **Usurpation d'identité** | Avec le secret JWT, n'importe qui peut générer un token JWT valide et se connecter en tant qu'admin sans connaître le mot de passe |
| **Élévation de privilèges** | L'attaquant forge un token avec le rôle `admin` et accède à toutes les fonctionnalités protégées |
| **Prise de contrôle totale** | Si l'application utilise le JWT pour toutes les authentifications, l'attaquant contrôle tous les comptes |
| **Persistance de l'attaque** | Le secret étant dans l'historique Git, même si le code est modifié, l'ancien commit reste accessible — le secret reste compromis |

**Scénario d'attaque concret :**
```
1. Attaquant voit sur GitHub : JWT_SECRET = "dvna-pfe-super-secret-jwt-2024"
2. Il génère un token forgé :
   jwt.sign({ id: 1, role: 'admin' }, 'dvna-pfe-super-secret-jwt-2024')
3. Il envoie ce token dans ses requêtes HTTP
4. Le serveur accepte le token comme valide → accès admin total
```

---

### Vulnérabilité 2 — Clé API admin hardcodée

**Fichier :** `server.js` — **Ligne 20**
**Règle Gitleaks :** `api-key-hardcoded`

#### Code vulnérable (ligne 20)

```javascript
// server.js — ligne 20
const ADMIN_API_KEY = "sk-dvna-admin-4f8b2c1d9e3a7f6b";
```

#### Qu'est-ce que c'est ?

`ADMIN_API_KEY` est une clé secrète qui permet d'accéder aux endpoints
d'administration de l'application (routes `/admin`, opérations sensibles, etc.).
C'est un second facteur d'authentification pour les opérations d'administration.

#### Pourquoi Gitleaks le détecte ?

- Le préfixe `sk-` est un pattern connu pour les clés API (similaire aux clés Stripe, OpenAI, etc.)
- Le nom `ADMIN_API_KEY` déclenche la règle `api-key-hardcoded`
- L'entropie `3.24` indique une chaîne suffisamment aléatoire pour être un secret

#### Risques

| Risque | Description |
|--------|-------------|
| **Accès non autorisé à l'administration** | Avec la clé API, l'attaquant peut appeler toutes les routes `/admin` de l'application |
| **Suppression ou modification de données** | Les routes admin permettent généralement des opérations destructrices (suppression d'utilisateurs, modification de rôles) |
| **Exfiltration de données** | L'accès admin donne accès à toutes les données de l'application |
| **Persistance dans l'historique Git** | Même supprimée du code, la clé reste visible dans les anciens commits |

**Scénario d'attaque concret :**
```
1. Attaquant voit sur GitHub : ADMIN_API_KEY = "sk-dvna-admin-4f8b2c1d9e3a7f6b"
2. Il envoie une requête :
   GET /admin/users
   Header: X-API-Key: sk-dvna-admin-4f8b2c1d9e3a7f6b
3. Le serveur accepte la requête → accès à toutes les données admin
```

---

## Solutions appliquées dans la branche `fix/gitleaks`

---

### Solution — Remplacement par des variables d'environnement

**Principe :**
Les secrets ne doivent **jamais** apparaître dans le code source versionné.
La solution consiste à les lire depuis les **variables d'environnement**
au moment de l'exécution de l'application.

#### Code corrigé

```javascript
// ============================================================
// AVANT — server.js lignes 19-20 (branche master)
// 2 secrets exposés publiquement sur GitHub
// ============================================================
const JWT_SECRET    = "dvna-pfe-super-secret-jwt-2024";       // ligne 19 ❌
const ADMIN_API_KEY = "sk-dvna-admin-4f8b2c1d9e3a7f6b";       // ligne 20 ❌


// ============================================================
// APRÈS — server.js lignes 19-20 (branche fix/gitleaks)
// Les secrets sont lus depuis l'environnement, jamais dans le code
// ============================================================
const JWT_SECRET    = process.env.JWT_SECRET    || 'changeme-in-prod';  // ligne 19 ✅
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'changeme-in-prod';  // ligne 20 ✅
```

#### Pourquoi cette solution ?

| Aspect | Explication |
|--------|-------------|
| **`process.env.JWT_SECRET`** | Node.js lit la variable d'environnement `JWT_SECRET` définie sur le serveur ou dans un fichier `.env` — elle n'est jamais écrite dans le code |
| **`\|\| 'changeme-in-prod'`** | Si la variable n'est pas définie, ce fallback indique explicitement qu'un vrai secret doit être configuré — c'est un signal d'avertissement, pas une vraie valeur de production |
| **Code source propre** | Le dépôt GitHub ne contient plus aucun secret — un attaquant qui accède au code ne trouve rien d'exploitable |
| **Séparation code / configuration** | C'est le principe **12-Factor App** : la configuration (secrets, URLs, ports) doit être séparée du code |

---

### Comment configurer les vraies valeurs ?

Les vraies valeurs des secrets sont stockées dans un fichier `.env`
sur le serveur, **jamais versionné sur GitHub** :

```bash
# Fichier .env — sur le serveur uniquement, jamais sur GitHub
JWT_SECRET=mon-vrai-secret-jwt-256-bits-complexe-ici
ADMIN_API_KEY=ma-vraie-cle-admin-complexe-ici
```

Ce fichier `.env` est **exclu du dépôt** grâce au fichier `.gitignore` :

```bash
# .gitignore
.env
.env.local
.env.production
```

**Vérification :** Gitleaks ne détectera plus rien car les vraies valeurs
ne sont pas dans le code — elles sont uniquement sur le serveur.

---

### Dans le contexte Docker / Jenkins

Dans le pipeline Jenkins ou Docker, les variables d'environnement
sont injectées directement sans fichier `.env` :

```groovy
// Dans le Jenkinsfile
environment {
    JWT_SECRET    = credentials('jwt-secret')
    ADMIN_API_KEY = credentials('admin-api-key')
}
```

```dockerfile
# Dans docker-compose ou docker run
docker run -e JWT_SECRET=mon-secret -e ADMIN_API_KEY=ma-cle dvna-app
```

---

## Bilan

| Secret | Fichier | Ligne | Avant | Après |
|--------|---------|-------|-------|-------|
| `JWT_SECRET` | `server.js` | 19 | `"dvna-pfe-super-secret-jwt-2024"` hardcodé | `process.env.JWT_SECRET` |
| `ADMIN_API_KEY` | `server.js` | 20 | `"sk-dvna-admin-4f8b2c1d9e3a7f6b"` hardcodé | `process.env.ADMIN_API_KEY` |

---

## Résultat après correction

```
Gitleaks scan — branche fix/gitleaks

Leaks found : 0   ✅
Pipeline Jenkins : PASS → continue vers Stage 3 (SAST)
```

---

## Principe DevSecOps appliqué — Secrets Management

> Un secret dans le code source est un secret **compromis**.
> Dès qu'il est commité sur un dépôt — même privé — il doit être
> considéré comme exposé et remplacé immédiatement.
>
> La règle fondamentale du **Secrets Management** en DevSecOps :
> **les secrets n'appartiennent pas au code, ils appartiennent à l'infrastructure.**

**Règle du pipeline Jenkins :**
Si Gitleaks détecte au moins 1 secret dans le code,
la pipeline s'arrête à la **Stage 2 (Secrets Detection)** —
le code ne progresse pas vers les étapes suivantes.

---

*Projet PFE DevSecOps — DVNA Pipeline Jenkins*
*Branche : `fix/gitleaks` | Outil : Gitleaks | Leaks : 2 → 0 | Date : 2026*

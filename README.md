# README — Branche `fix/sca` : Corrections SCA (npm audit)

## Contexte

L'analyse SCA (Software Composition Analysis) a été réalisée avec **npm audit**
sur les dépendances Node.js de DVNA (Damn Vulnerable Node Application).

npm audit compare chaque package déclaré dans `package.json` contre la base de données
officielle des vulnérabilités connues (CVEs et GitHub Security Advisories).

**Résultat du scan :**
```
Commande  : npm audit --audit-level=critical
Fichier   : package.json
Résultat  : 13 vulnerabilities (5 low, 1 moderate, 4 high, 3 critical)
```

Le pipeline Jenkins s'arrête dès qu'une vulnérabilité CRITICAL est détectée —
la branche `fix/sca` corrige l'ensemble des 13 vulnérabilités.

---

## Les 13 vulnérabilités détectées — Rapport brut

```
Package          Sévérité    Détail
──────────────── ─────────── ──────────────────────────────────────────────
node-serialize   CRITICAL    Code Execution through IIFE (CVE-2017-5941)
xmldom           CRITICAL    Misinterpretation of malicious XML input (3 CVEs)
ejs              CRITICAL    Template injection vulnerability (GHSA-phwq-j96m)
body-parser      HIGH        Denial of Service when url encoding is enabled
qs               HIGH        Prototype Pollution + DoS (3 advisories)
path-to-regexp   HIGH        ReDoS via backtracking regex (3 advisories)
send             HIGH        Template injection → XSS
express          HIGH        Dépend de body-parser, cookie, path-to-regexp, qs, send
express-session  (indirect)  Dépend de cookie et on-headers vulnérables
cookie           (indirect)  Out of bounds characters acceptés
on-headers       (indirect)  HTTP response header manipulation
serve-static     (indirect)  Dépend de send vulnérable
brace-expansion  MODERATE    Zero-step sequence → process hang + memory exhaustion
```

---

## Détail des vulnérabilités et corrections

---

### Vulnérabilité 1 — `node-serialize` — CRITICAL

**Package :** `node-serialize`
**Version vulnérable :** `*` (toutes versions)
**Sévérité :** CRITICAL
**Advisory :** GHSA-q4v7-4rhw-9hqm
**Lien :** https://github.com/advisories/GHSA-q4v7-4rhw-9hqm

#### Message npm audit
```
node-serialize  *
Severity: critical
Code Execution through IIFE in node-serialize
No fix available
node_modules/node-serialize
```

#### Explication

`node-serialize` est un package qui sérialise et désérialise des objets JavaScript,
y compris des fonctions. Pour reconstruire les fonctions lors de la désérialisation,
il utilise `eval()` en interne. Si un attaquant envoie un objet contenant
une fonction auto-invoquée (IIFE), cette fonction est **exécutée immédiatement**
sur le serveur au moment de la désérialisation.
C'est la vulnérabilité **CVE-2017-5941** — l'une des plus dangereuses en Node.js.

#### Risques

| Risque | Description |
|--------|-------------|
| **Remote Code Execution (RCE)** | L'attaquant exécute du code JavaScript arbitraire sur le serveur |
| **Contrôle total** | Lecture de fichiers, installation de backdoor, suppression de données |
| **Aucun correctif disponible** | Le package est abandonné — pas de version corrigée possible |
| **CVE-2017-5941 (CRITICAL)** | Exploit public connu et documenté depuis 2017 |

**Payload d'attaque (CVE-2017-5941) :**
```javascript
// Envoyé dans req.body.payload via HTTP POST :
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('whoami')}()"}
// → node-serialize voit "_$$ND_FUNC$$_" → eval() exécute la fonction
// → exec('whoami') s'exécute sur le serveur → RCE confirmé
```

#### Correction appliquée dans `fix/sca`

**Aucun correctif disponible** — le package doit être supprimé et remplacé.

```json
// AVANT — package.json (master)
"dependencies": {
  "node-serialize": "0.0.4"   // ❌ CRITICAL — aucun fix disponible
}

// APRÈS — fix/sca
"dependencies": {
  // node-serialize supprimé entièrement
  // La désérialisation dans server.js a été remplacée par JSON.parse()
  // (fait dans la branche fix/sast)
}
```

```javascript
// AVANT — server.js ligne 135 (master)
const data = serialize.unserialize(req.body.payload);
// ❌ RCE possible via IIFE — CVE-2017-5941

// APRÈS — fix/sca (déjà fait dans fix/sast)
const data = JSON.parse(req.body.payload);
// ✅ JSON.parse() ne peut pas exécuter de code
```

**Pourquoi cette solution :**
`node-serialize` est abandonné depuis 2017, aucune mise à jour n'est prévue.
La seule option est la suppression complète.
`JSON.parse()` est le remplacement naturel pour traiter des données
JSON — il ne peut jamais exécuter de code.

---

### Vulnérabilité 2 — `xmldom` — CRITICAL

**Package :** `xmldom`
**Version vulnérable :** `*` (toutes versions)
**Sévérité :** CRITICAL
**Advisories :** GHSA-h6q6-9hqw-rwfv, GHSA-crh6-fp67-6883, GHSA-5fg8-2547-mr8q
**Lien :** https://github.com/advisories/GHSA-h6q6-9hqw-rwfv

#### Message npm audit
```
xmldom  *
Severity: critical
Misinterpretation of malicious XML input - GHSA-h6q6-9hqw-rwfv
xmldom allows multiple root nodes in a DOM - GHSA-crh6-fp67-6883
Misinterpretation of malicious XML input - GHSA-5fg8-2547-mr8q
No fix available
node_modules/xmldom
```

#### Explication

`xmldom` est un parser XML pour Node.js. Il souffre de **3 vulnérabilités critiques** :
- Il accepte des documents XML malformés avec plusieurs nœuds racines,
  ce qui peut contourner des vérifications de sécurité basées sur la structure XML
- Il interprète mal certains inputs XML malveillants, permettant
  l'injection d'entités externes (XXE — XML External Entity)
- Un attaquant peut envoyer un document XML spécialement conçu
  pour tromper le parser et lire des fichiers système ou déclencher des SSRF

#### Risques

| Risque | Description |
|--------|-------------|
| **XXE (XML External Entity)** | Lecture de fichiers système sensibles via des entités XML externes |
| **SSRF** | Forçage du serveur à effectuer des requêtes vers des ressources internes |
| **Bypass de validation** | Structure XML malformée contourne les vérifications de sécurité |
| **Aucun correctif disponible** | Package abandonné — 3 CVEs sans fix |

**Payload d'attaque XXE :**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
<!-- xmldom traite l'entité → retourne le contenu de /etc/passwd -->
```

#### Correction appliquée dans `fix/sca`

**Aucun correctif disponible** — le package doit être supprimé.

```json
// AVANT — package.json (master)
"dependencies": {
  "xmldom": "0.1.31"   // ❌ CRITICAL — 3 CVEs sans fix disponible
}

// APRÈS — fix/sca
"dependencies": {
  // xmldom supprimé entièrement
  // Les require('xmldom') orphelins dans server.js ont été supprimés
}
```

**Pourquoi cette solution :**
`xmldom` est abandonné et aucune version corrigée n'existe.
Les références à `xmldom` dans `server.js` étaient déjà orphelines
(non utilisées fonctionnellement) — leur suppression n'impacte pas l'application.

---

### Vulnérabilité 3 — `ejs` — CRITICAL

**Package :** `ejs`
**Version vulnérable :** `<= 3.1.9`
**Sévérité :** CRITICAL
**Advisories :** GHSA-phwq-j96m-2c2q, GHSA-ghr5-ch3p-vcr6
**Lien :** https://github.com/advisories/GHSA-phwq-j96m-2c2q

#### Message npm audit
```
ejs  <=3.1.9
Severity: critical
ejs template injection vulnerability - GHSA-phwq-j96m-2c2q
ejs lacks certain pollution protection - GHSA-ghr5-ch3p-vcr6
fix available via `npm audit fix --force`
Will install ejs@3.1.10, which is outside the stated dependency range
node_modules/ejs
```

#### Explication

EJS (Embedded JavaScript) est le moteur de templates utilisé par DVNA
pour générer les pages HTML. La version `<= 3.1.9` souffre de deux problèmes :
- Une vulnérabilité d'**injection de template côté serveur (SSTI)**
  via le paramètre `outputFunctionName` qui permet d'exécuter du code arbitraire
- Un manque de protection contre la **pollution de prototype** JavaScript,
  ce qui peut modifier le comportement de tous les objets de l'application

#### Risques

| Risque | Description |
|--------|-------------|
| **Server-Side Template Injection (SSTI)** | Exécution de code JavaScript arbitraire via le moteur de template |
| **Remote Code Execution** | Via SSTI, l'attaquant peut exécuter des commandes système |
| **Prototype Pollution** | Modification des prototypes JavaScript → comportement imprévisible de l'application |
| **Contournement de sécurité** | La pollution de prototype peut désactiver des mécanismes de validation |

**Payload d'attaque SSTI :**
```javascript
// Paramètre envoyé dans la requête :
outputFunctionName=x;process.mainModule.require('child_process').exec('whoami')//
// → EJS exécute ce code lors du rendu du template → RCE
```

#### Correction appliquée dans `fix/sca`

**Correctif disponible** — mise à jour vers `ejs@3.1.10`.

```json
// AVANT — package.json (master)
"dependencies": {
  "ejs": "3.1.6"    // ❌ CRITICAL — SSTI + prototype pollution
}

// APRÈS — fix/sca
"dependencies": {
  "ejs": "^3.1.10"  // ✅ Version corrigée — SSTI et pollution corrigés
}
```

**Pourquoi cette solution :**
La version `3.1.10` corrige spécifiquement la vulnérabilité SSTI
en désactivant le paramètre `outputFunctionName` par défaut
et en renforçant la protection contre la pollution de prototype.

---

### Vulnérabilité 4 — `body-parser` — HIGH

**Package :** `body-parser`
**Version vulnérable :** `<= 1.20.2`
**Sévérité :** HIGH
**Advisory :** GHSA-qwcr-r2fm-qrc7
**Lien :** https://github.com/advisories/GHSA-qwcr-r2fm-qrc7

#### Message npm audit
```
body-parser  <=1.20.2
Severity: high
body-parser vulnerable to denial of service when url encoding is enabled
Depends on vulnerable versions of qs
fix available via `npm audit fix --force`
Will install express@4.22.1, which is outside the stated dependency range
node_modules/body-parser
```

#### Explication

`body-parser` parse le corps des requêtes HTTP entrantes.
Quand le décodage URL (`urlencoded`) est activé, une requête malformée
peut provoquer une consommation excessive de CPU ou de mémoire,
rendant le serveur incapable de traiter d'autres requêtes.
`body-parser` dépend aussi de `qs` en version vulnérable (voir vulnérabilité 5).

#### Risques

| Risque | Description |
|--------|-------------|
| **Denial of Service (DoS)** | Une requête malformée consomme tout le CPU → serveur indisponible |
| **Disponibilité** | L'application ne répond plus aux requêtes légitimes |
| **Amplification** | Quelques requêtes suffisent à saturer le serveur |

#### Correction appliquée dans `fix/sca`

**Correctif disponible** via mise à jour d'`express` vers `4.22.1`.

```json
// AVANT — package.json (master)
"dependencies": {
  "express": "4.17.1"   // ❌ inclut body-parser <=1.20.2 vulnérable
}

// APRÈS — fix/sca
"dependencies": {
  "express": "^4.22.1"  // ✅ inclut body-parser >=1.20.3 corrigé
}
```

**Pourquoi cette solution :**
`body-parser` est une dépendance interne d'`express`.
Mettre à jour `express` vers `^4.22.1` met automatiquement à jour
`body-parser` vers une version corrigée.

---

### Vulnérabilité 5 — `qs` — HIGH

**Package :** `qs`
**Version vulnérable :** `<= 6.14.1`
**Sévérité :** HIGH
**Advisories :** GHSA-hrpp-h998-j3pp, GHSA-w7fw-mjwx-w883, GHSA-6rw7-vpxm-498p
**Lien :** https://github.com/advisories/GHSA-hrpp-h998-j3pp

#### Message npm audit
```
qs  <=6.14.1
Severity: high
qs vulnerable to Prototype Pollution - GHSA-hrpp-h998-j3pp
qs's arrayLimit bypass in comma parsing allows denial of service - GHSA-w7fw-mjwx-w883
qs's arrayLimit bypass in its bracket notation allows DoS via memory exhaustion - GHSA-6rw7-vpxm-498p
fix available via `npm audit fix --force`
Will install express@4.22.1, which is outside the stated dependency range
node_modules/qs
```

#### Explication

`qs` est la librairie de parsing des query strings (paramètres d'URL) utilisée par Express.
Elle souffre de **3 vulnérabilités** :
- **Prototype Pollution** : un paramètre URL spécialement formé peut modifier
  le prototype d'objets JavaScript globaux, altérant le comportement de l'application
- **DoS via comma parsing** : contournement de la limite de tableaux via la virgule
- **DoS via bracket notation** : épuisement mémoire via la notation entre crochets

#### Risques

| Risque | Description |
|--------|-------------|
| **Prototype Pollution** | Modification des objets globaux JavaScript → comportement imprévisible |
| **Contournement de sécurité** | Pollution du prototype peut désactiver des validations |
| **Denial of Service** | Deux vecteurs DoS indépendants → saturation mémoire |
| **Amplification** | Quelques requêtes suffisent à épuiser la mémoire du serveur |

**Payload d'attaque (Prototype Pollution) :**
```
GET /search?__proto__[admin]=true
→ qs parse cela comme : obj.__proto__.admin = true
→ Tous les objets héritent de admin=true → bypass de vérification de rôle
```

#### Correction appliquée dans `fix/sca`

**Correctif disponible** via mise à jour d'`express` vers `4.22.1`.

```json
// AVANT — package.json (master)
"dependencies": {
  "express": "4.17.1"   // ❌ inclut qs <=6.14.1 — 3 vulnérabilités
}

// APRÈS — fix/sca
"dependencies": {
  "express": "^4.22.1"  // ✅ inclut qs >=6.14.2 corrigé
}
```

---

### Vulnérabilité 6 — `path-to-regexp` — HIGH

**Package :** `path-to-regexp`
**Version vulnérable :** `<= 0.1.12`
**Sévérité :** HIGH
**Advisories :** GHSA-9wv6-86v2-598j, GHSA-rhx6-c78j-4q9w, GHSA-37ch-88jc-xwx2
**Lien :** https://github.com/advisories/GHSA-9wv6-86v2-598j

#### Message npm audit
```
path-to-regexp  <=0.1.12
Severity: high
path-to-regexp outputs backtracking regular expressions - GHSA-9wv6-86v2-598j
path-to-regexp contains a ReDoS - GHSA-rhx6-c78j-4q9w
path-to-regexp vulnerable to Regular Expression Denial of Service
  via multiple route parameters - GHSA-37ch-88jc-xwx2
fix available via `npm audit fix --force`
Will install express@4.22.1, which is outside the stated dependency range
node_modules/path-to-regexp
```

#### Explication

`path-to-regexp` convertit les routes Express (ex: `/user/:id`) en expressions régulières.
Les versions vulnérables génèrent des regex avec du **backtracking catastrophique** :
sur certains patterns d'URL, le moteur regex peut mettre un temps
**exponentiel** à s'exécuter, bloquant le thread Node.js pendant des secondes
et rendant le serveur inaccessible.
C'est une attaque **ReDoS** (Regular Expression Denial of Service).

#### Risques

| Risque | Description |
|--------|-------------|
| **ReDoS** | Une URL spécialement formée bloque le thread Node.js pendant plusieurs secondes |
| **Denial of Service** | Quelques requêtes suffisent à rendre le serveur totalement inaccessible |
| **Thread unique** | Node.js est mono-thread → une regex bloquante paralyse toute l'application |

**Payload d'attaque (ReDoS) :**
```
GET /user/aaaaaaaaaaaaaaaaaaaaaaaaaaa!
→ path-to-regexp évalue la regex avec backtracking catastrophique
→ CPU à 100% pendant plusieurs secondes → serveur bloqué
```

#### Correction appliquée dans `fix/sca`

**Correctif disponible** via mise à jour d'`express` vers `4.22.1`.

```json
// AVANT — package.json (master)
"dependencies": {
  "express": "4.17.1"   // ❌ inclut path-to-regexp <=0.1.12 — ReDoS
}

// APRÈS — fix/sca
"dependencies": {
  "express": "^4.22.1"  // ✅ inclut path-to-regexp >=0.1.13 corrigé
}
```

---

### Vulnérabilité 7 — `send` — HIGH

**Package :** `send`
**Version vulnérable :** `< 0.19.0`
**Sévérité :** HIGH
**Advisory :** GHSA-m6fv-jmcg-4jfg
**Lien :** https://github.com/advisories/GHSA-m6fv-jmcg-4jfg

#### Message npm audit
```
send  <0.19.0
send vulnerable to template injection that can lead to XSS
fix available via `npm audit fix --force`
Will install express@4.22.1, which is outside the stated dependency range
node_modules/send
  serve-static  <=1.16.0
  Depends on vulnerable versions of send
  node_modules/serve-static
```

#### Explication

`send` est le module qu'Express utilise pour envoyer des fichiers statiques.
Dans les versions vulnérables, lors de l'envoi de pages d'erreur (404, 403...),
le chemin de fichier demandé est inséré sans échappement dans la réponse HTML.
Un attaquant peut injecter du code HTML/JavaScript dans une URL
pour déclencher un **XSS réfléchi** via les pages d'erreur.
`serve-static` dépend de `send` et est donc également affecté.

#### Risques

| Risque | Description |
|--------|-------------|
| **XSS réfléchi** | Injection de scripts dans les pages d'erreur générées par Express |
| **Vol de session** | Script injecté → vol du cookie de session de la victime |
| **Phishing** | Pages d'erreur falsifiées pour tromper l'utilisateur |

#### Correction appliquée dans `fix/sca`

**Correctif disponible** via mise à jour d'`express` vers `4.22.1`.

```json
// AVANT — package.json (master)
"dependencies": {
  "express": "4.17.1"   // ❌ inclut send <0.19.0 → XSS dans pages d'erreur
}

// APRÈS — fix/sca
"dependencies": {
  "express": "^4.22.1"  // ✅ inclut send >=0.19.0 corrigé
}
```

---

### Vulnérabilité 8 — `brace-expansion` — MODERATE

**Package :** `brace-expansion`
**Version vulnérable :** `2.0.0 - 2.0.2`
**Sévérité :** MODERATE
**Advisory :** GHSA-f886-m6hf-6m8v
**Lien :** https://github.com/advisories/GHSA-f886-m6hf-6m8v

#### Message npm audit
```
brace-expansion  2.0.0 - 2.0.2
Severity: moderate
brace-expansion: Zero-step sequence causes process hang and memory exhaustion
fix available via `npm audit fix`
node_modules/brace-expansion
```

#### Explication

`brace-expansion` est une dépendance indirecte utilisée pour l'expansion
de patterns comme `{a,b,c}` ou `{1..10}`. Dans les versions `2.0.0` à `2.0.2`,
une séquence avec un pas nul (ex: `{0..100..0}`) crée une boucle infinie,
provoquant un blocage complet du processus Node.js et une saturation mémoire.

#### Risques

| Risque | Description |
|--------|-------------|
| **Process hang** | Le processus Node.js se bloque indéfiniment |
| **Memory exhaustion** | Saturation de la mémoire → crash du serveur |
| **Denial of Service** | Serveur inaccessible jusqu'au redémarrage |

#### Correction appliquée dans `fix/sca`

**Correctif disponible** via `npm audit fix` ou forçage de version.

```json
// AVANT — package.json (master)
// brace-expansion 2.0.0-2.0.2 installée en dépendance indirecte
// ❌ Séquence à pas nul → boucle infinie → DoS

// APRÈS — fix/sca
// Ajout d'un bloc "overrides" pour forcer la version corrigée
{
  "overrides": {
    "brace-expansion": "^2.0.3"   // ✅ Version corrigée forcée
  }
}
```

**Pourquoi cette solution :**
`brace-expansion` est une dépendance **indirecte** — elle n'est pas
déclarée directement dans `package.json` mais installée par une autre dépendance.
Le bloc `overrides` dans `package.json` force npm à utiliser
la version corrigée `^2.0.3` pour toute la chaîne de dépendances.

---

### Vulnérabilités indirectes — `cookie`, `on-headers`, `express-session`, `serve-static`

Ces packages sont des **dépendances indirectes** corrigées automatiquement
par la mise à jour d'`express` vers `^4.22.1` et d'`express-session` vers `^1.18.1`.

| Package | Problème | Correction |
|---------|----------|------------|
| `cookie < 0.7.0` | Accepte des caractères hors limites dans nom/path/domain du cookie | Corrigé via `express@^4.22.1` |
| `on-headers < 1.1.0` | Manipulation des headers de réponse HTTP | Corrigé via `express-session@^1.18.1` |
| `serve-static <= 1.16.0` | Dépend de `send` vulnérable → XSS dans pages d'erreur | Corrigé via `express@^4.22.1` |

---

## Résumé des corrections dans `package.json`

```json
// ================================================================
// AVANT — package.json (branche master)
// 13 vulnérabilités détectées
// ================================================================
{
  "dependencies": {
    "body-parser":    "1.19.0",     // ❌ HIGH  — DoS URL encoding
    "ejs":            "3.1.6",      // ❌ CRITICAL — SSTI + prototype pollution
    "express":        "4.17.1",     // ❌ HIGH  — multiple vulnérabilités indirectes
    "express-session": "1.17.1",    // ❌ (indirect) cookie + on-headers vulnérables
    "node-serialize": "0.0.4",      // ❌ CRITICAL — RCE CVE-2017-5941
    "xmldom":         "0.1.31"      // ❌ CRITICAL — XXE, 3 CVEs sans fix
  }
}

// ================================================================
// APRÈS — package.json (branche fix/sca)
// 0 vulnérabilité
// ================================================================
{
  "dependencies": {
    "body-parser":    "^1.20.3",    // ✅ DoS corrigé
    "ejs":            "^3.1.10",    // ✅ SSTI + pollution corrigés
    "express":        "^4.22.1",    // ✅ Toutes vulnérabilités indirectes corrigées
    "express-session": "^1.18.1",   // ✅ cookie + on-headers corrigés
    // node-serialize → SUPPRIMÉ    // ✅ Aucun fix possible — supprimé
    // xmldom → SUPPRIMÉ            // ✅ Aucun fix possible — supprimé
  },
  "overrides": {
    "brace-expansion": "^2.0.3"     // ✅ DoS dépendance indirecte corrigé
  }
}
```

---

## Bilan complet — 13 vulnérabilités AVANT / APRÈS

| # | Package | Sévérité | Problème | Correction |
|---|---------|----------|----------|------------|
| 1 | `node-serialize` | CRITICAL | RCE via IIFE — CVE-2017-5941 | **Supprimé** — remplacé par `JSON.parse()` |
| 2 | `xmldom` | CRITICAL | XXE — 3 CVEs sans fix | **Supprimé** — imports orphelins retirés |
| 3 | `ejs` | CRITICAL | SSTI + prototype pollution | Mis à jour → `^3.1.10` |
| 4 | `body-parser` | HIGH | DoS via URL encoding | Corrigé via `express@^4.22.1` |
| 5 | `qs` | HIGH | Prototype Pollution + DoS (x3) | Corrigé via `express@^4.22.1` |
| 6 | `path-to-regexp` | HIGH | ReDoS via backtracking (x3) | Corrigé via `express@^4.22.1` |
| 7 | `send` | HIGH | XSS dans pages d'erreur | Corrigé via `express@^4.22.1` |
| 8 | `brace-expansion` | MODERATE | DoS — boucle infinie | Forcé → `^2.0.3` via `overrides` |
| 9 | `cookie` | (indirect) | Out of bounds dans cookies | Corrigé via `express@^4.22.1` |
| 10 | `on-headers` | (indirect) | Manipulation headers HTTP | Corrigé via `express-session@^1.18.1` |
| 11 | `express-session` | (indirect) | Dépend de cookie + on-headers | Mis à jour → `^1.18.1` |
| 12 | `serve-static` | (indirect) | Dépend de `send` vulnérable | Corrigé via `express@^4.22.1` |
| 13 | `express` | HIGH | Dépend de 5 packages vulnérables | Mis à jour → `^4.22.1` |

---

## Résultat après correction

```
npm audit --audit-level=critical — branche fix/sca

Vulnerabilities found : 0   ✅
Pipeline Jenkins       : PASS → continue vers Stage 5 (Image Scan / Trivy)
```

---

## Principe DevSecOps appliqué — Software Composition Analysis

> La majorité des applications modernes sont composées à **80% de code tiers**
> (packages npm, librairies open-source). Une seule dépendance vulnérable
> peut compromettre toute l'application, même si le code maison est parfait.
>
> Le SCA automatise la surveillance de toutes ces dépendances
> et bloque le pipeline dès qu'une vulnérabilité critique est détectée.

**Deux stratégies selon la situation :**
- **Package avec correctif disponible** → mettre à jour vers la version corrigée
- **Package sans correctif (abandonné)** → supprimer et remplacer par une alternative sûre

**Règle du pipeline Jenkins :**
Si `npm audit` détecte au moins 1 vulnérabilité de niveau `critical`,
le pipeline s'arrête à la **Stage 4 (SCA)** — le code ne progresse pas
vers les étapes suivantes (Image Scan, IaC, DAST).

---

*Projet PFE DevSecOps — DVNA Pipeline Jenkins*
*Branche : `fix/sca` | Outil : npm audit | Vulnérabilités : 13 → 0 | Date : 2026*

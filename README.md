# Fix/SCA — Correction des vulnérabilités de dépendances (npm audit)

## Contexte

Cette branche corrige les vulnérabilités détectées par **npm audit** (Stage 3 du pipeline DevSecOps).
npm audit analyse les packages Node.js déclarés dans `package.json` et les compare 
à une base de données de vulnérabilités connues (CVEs).

---

## Vulnérabilités détectées sur master

| Package | Version vulnérable | Sévérité | CVE | Problème |
|---|---|---|---|---|
| node-serialize | 0.0.4 | CRITIQUE | CVE-2017-5941 | RCE via désérialisation IIFE |
| xmldom | 0.1.31 | CRITIQUE | CVE-2022-39353 | Parsing XML malveillant (XXE) |
| ejs | 3.1.6 | CRITIQUE | CVE-2022-29078 | Injection de template (SSTI) |
| express | 4.17.1 | ÉLEVÉ | multiple | DoS, ReDoS, prototype pollution |
| body-parser | 1.19.0 | ÉLEVÉ | GHSA-qwcr | DoS via URL encoding |
| brace-expansion | 2.0.0-2.0.2 | MODÉRÉ | GHSA-f886 | DoS mémoire |
| fast-xml-parser | <5.5.9 | MODÉRÉ | GHSA-jp2q | Entity Expansion Limits bypass |

---

## Corrections appliquées

### 1. Suppression des packages sans correctif disponible

**`node-serialize@0.0.4`** — supprimé car :
- Vulnérabilité critique CVE-2017-5941 (RCE)
- Package abandonné, aucun correctif disponible
- Remplacé par `JSON.parse()` dans `server.js` (fait dans fix/sast)

**`xmldom@0.1.31`** — supprimé car :
- 3 CVEs critiques sans correctif disponible
- Package abandonné
- Remplacé par `fast-xml-parser` qui est maintenu activement

### 2. Mise à jour des packages avec correctifs disponibles

**`express`** : `4.17.1` → `^4.22.1`
- Corrige DoS, ReDoS sur path-to-regexp
- Corrige prototype pollution sur qs
- Corrige XSS sur send/serve-static

**`express-session`** : `1.17.1` → `^1.18.1`
- Corrige la gestion des cookies vulnérables

**`ejs`** : `3.1.6` → `^3.1.10`
- Corrige l'injection de template SSTI (CVE-2022-29078)
- Corrige la pollution de prototype

**`body-parser`** : `1.19.0` → `^1.20.3`
- Corrige le déni de service via URL encoding

**`fast-xml-parser`** : `^4.3.0` → `^5.5.9`
- Corrige le bypass des limites d'expansion d'entités

### 3. Forçage de la version de brace-expansion

Ajout d'un bloc `overrides` dans `package.json` pour forcer
la version corrigée de `brace-expansion` (dépendance indirecte) :
```json
"overrides": {
  "brace-expansion": "^2.0.3"
}
```

---

## Fichiers modifiés

| Fichier | Modification |
|---|---|
| `package.json` | Mise à jour et suppression des dépendances vulnérables |
| `Jenkinsfile` | Ajout de `npm install` avant `npm audit` |

---

## Résultat après correction
```
npm install → added 2 packages, removed 4 packages, changed 48 packages
npm audit   → found 0 vulnerabilities
```

**Stage 3 SCA** : ❌ FAIL sur master → ✅ PASS sur fix/sca

---

## Commande de vérification
```bash
npm audit --audit-level=critical
# Résultat attendu : found 0 vulnerabilities
```

---

## Leçon DevSecOps

> En DevSecOps, l'analyse des dépendances (SCA) est essentielle car 
> la majorité des applications modernes reposent sur des packages tiers.
> Un seul package vulnérable peut compromettre toute l'application.
> Il faut distinguer :
> - Les packages **avec correctif** → mettre à jour
> - Les packages **sans correctif** → supprimer et remplacer

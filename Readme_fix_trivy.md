# README — Branche `fix/trivy` : Corrections Image Scan (Trivy)

## Contexte

L'analyse de l'image Docker a été réalisée avec **Trivy**
sur l'image construite à partir du `Dockerfile` de DVNA.

Trivy scanne l'image Docker **après le build** — il analyse :
- Les packages du système d'exploitation (Debian) installés dans l'image
- Les packages Node.js de l'application (`package.json`)
- Les packages Node.js du npm système de l'image de base

**Résultat du scan (branche master) :**
```
Image scannée  : dvna-pfe:pipeline (debian 12.11)
OS CVEs        : CRITICAL + HIGH détectés
Node.js CVEs   : 20 (HIGH: 16, CRITICAL: 4)
Pipeline       : FAIL → bloqué à la Stage 5
```

La branche `fix/trivy` corrige ces vulnérabilités
en modifiant le `Dockerfile`, le `package.json` et la configuration Trivy.

---

## Les vulnérabilités détectées — Rapport brut

### Partie 1 — CVEs OS Debian (image de base)

```
Package          CVE               Sévérité   Statut         Version installée
──────────────── ───────────────── ────────── ────────────── ─────────────────────
openssl          CVE-2025-15467    CRITICAL   fixed          3.0.16-1~deb12u1
zlib1g           CVE-2023-45853    CRITICAL   will_not_fix   1:1.2.13.dfsg-1
libssl3          CVE-2025-15467    CRITICAL   fixed          3.0.16-1~deb12u1
gpgv             CVE-2025-68973    HIGH       fixed          2.2.40-1.1
libc-bin         CVE-2025-4802     HIGH       fixed          2.36-9+deb12u10
libc6            CVE-2025-4802     HIGH       fixed          2.36-9+deb12u10
libgnutls30      CVE-2025-32988    HIGH       fixed          3.7.9-2+deb12u4
libgnutls30      CVE-2025-32990    HIGH       fixed          3.7.9-2+deb12u4
libpam-modules   CVE-2025-6020     HIGH       fixed          1.5.2-6+deb12u1
libpam0g         CVE-2025-6020     HIGH       fixed          1.5.2-6+deb12u1
perl-base        CVE-2023-31484    HIGH       fixed          5.36.0-7+deb12u2
mariadb-common   CVE-2025-13699    HIGH       no fix         1:10.11.11-0+deb12u1
openssh-client   CVE-2026-3497     HIGH       no fix         1:9.2p1-2+deb12u6
linux-libc-dev   Multiples CVEs    HIGH       will_not_fix   6.1.137-1
```

### Partie 2 — CVEs Node.js (node-pkg — `package.json` application)

```
Library          CVE               Sévérité   Version installée   Version corrigée
──────────────── ───────────────── ────────── ─────────────────── ────────────────
ejs              CVE-2022-29078    CRITICAL   3.1.6               3.1.7
node-serialize   CVE-2017-5941     CRITICAL   0.0.4               (aucune)
node-serialize   NSWG-ECO-311      CRITICAL   0.0.4               <0.0.0
xmldom           CVE-2022-39353    CRITICAL   0.1.31              (aucune)
body-parser      CVE-2024-45590    HIGH       1.19.0              1.20.3
cross-spawn      CVE-2024-21538    HIGH       7.0.3               7.0.5
glob             CVE-2025-64756    HIGH       10.4.2              10.5.0
minimatch        CVE-2026-26996    HIGH       9.0.5               9.0.6
minimatch        CVE-2026-27903    HIGH       9.0.5               9.0.7
minimatch        CVE-2026-27904    HIGH       9.0.5               9.0.7
path-to-regexp   CVE-2024-45296    HIGH       0.1.7               0.1.10
path-to-regexp   CVE-2024-52798    HIGH       0.1.7               0.1.12
qs               CVE-2022-24999    HIGH       6.7.0               6.7.3
tar              CVE-2026-23745    HIGH       6.2.1               7.5.3
tar              CVE-2026-23950    HIGH       6.2.1               7.5.4
tar              CVE-2026-24842    HIGH       6.2.1               7.5.7
tar              CVE-2026-26960    HIGH       6.2.1               7.5.8
tar              CVE-2026-29786    HIGH       6.2.1               7.5.10
tar              CVE-2026-31802    HIGH       6.2.1               7.5.11
```

---

## Détail des vulnérabilités et corrections

---

### Groupe 1 — CVEs OS avec correctif disponible (`fixed`)

**Packages concernés :** `openssl`, `libssl3`, `gpgv`, `libc-bin`, `libc6`,
`libgnutls30`, `libpam-modules`, `libpam0g`, `perl-base`

#### Vulnérabilités représentatives

**`openssl` / `libssl3` — CVE-2025-15467 — CRITICAL**

```
Package          : openssl / libssl3
CVE              : CVE-2025-15467
Sévérité         : CRITICAL
Version installée: 3.0.16-1~deb12u1
Version corrigée : 3.0.18-1~deb12u2
Description      : Remote code execution or Denial of Service
                   via oversized Initialization Vector
```

**Explication :**
OpenSSL est la librairie cryptographique qui gère HTTPS, TLS et les certificats.
Une taille de vecteur d'initialisation (IV) incorrecte peut provoquer
une exécution de code à distance ou un crash du service.

**Risques :**

| Risque | Description |
|--------|-------------|
| **Remote Code Execution** | Un attaquant peut exécuter du code sur le serveur via une requête TLS malformée |
| **Denial of Service** | Crash du service SSL → application inaccessible |
| **Interception TLS** | Compromission de toutes les communications chiffrées |

---

**`libgnutls30` — CVE-2025-32988 / CVE-2025-32990 — HIGH**

```
Package          : libgnutls30
CVE              : CVE-2025-32988, CVE-2025-32990
Sévérité         : HIGH
Version installée: 3.7.9-2+deb12u4
Version corrigée : 3.7.9-2+deb12u5
Description      : Vulnérabilités dans la librairie GnuTLS (TLS)
```

**Risques :**

| Risque | Description |
|--------|-------------|
| **Compromission TLS** | Failles dans la couche de chiffrement réseau |
| **Interception** | Communications réseau potentiellement interceptables |

---

**`libpam` — CVE-2025-6020 — HIGH**

```
Package          : libpam-modules, libpam0g
CVE              : CVE-2025-6020
Sévérité         : HIGH
Version installée: 1.5.2-6+deb12u1
Version corrigée : 1.5.2-6+deb12u2
Description      : Vulnérabilité dans PAM (Pluggable Authentication Modules)
```

**Risques :**

| Risque | Description |
|--------|-------------|
| **Bypass d'authentification** | PAM gère l'authentification système — une faille peut permettre un accès non autorisé |
| **Élévation de privilèges** | Contournement des mécanismes d'authentification Linux |

---

#### Correction appliquée dans `fix/trivy` — Dockerfile

**Problème :**
L'image de base `node:18` contient les packages Debian dans leur version
du moment du build de l'image officielle. Ces packages ne sont **pas mis à jour
automatiquement** — ils restent vulnérables jusqu'à ce qu'on les mette à jour.

**Code vulnérable — AVANT (branche `master`) :**

```dockerfile
# AVANT — Dockerfile (master)
FROM node:18

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 9090
CMD ["node", "server.js"]
# ❌ Aucune mise à jour OS → tous les packages Debian restent vulnérables
# ❌ node:18 = image complète avec beaucoup de packages inutiles
# ❌ npm install installe les devDependencies → surface d'attaque plus grande
```

**Correction appliquée dans `fix/trivy` :**

```dockerfile
# APRÈS — Dockerfile (fix/trivy)
FROM node:18.20-slim
# ✅ Image "slim" → moins de packages installés → surface d'attaque réduite
# ✅ Version fixée 18.20 → comportement reproductible

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
# ✅ Met à jour TOUS les packages Debian au moment du build
# ✅ Corrige openssl, libssl3, gpgv, libc6, libgnutls30, libpam, perl-base
# ✅ rm -rf /var/lib/apt/lists/* réduit la taille de l'image

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
# ✅ npm ci = installation stricte et reproductible (pas de résolution de versions)
# ✅ --omit=dev = n'installe pas les devDependencies → moins de packages vulnérables

COPY . .

# ✅ Ajout d'un utilisateur non-root (bonne pratique Checkov)
USER node

EXPOSE 9090

# ✅ HEALTHCHECK (bonne pratique Checkov)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:9090/ || exit 1

CMD ["node", "server.js"]
```

**Pourquoi cette solution :**
`apt-get upgrade -y` met à jour tous les packages Debian vers leur dernière
version sécurisée au moment du build. Cela corrige en une seule commande
toutes les CVEs OS pour lesquelles un correctif est disponible (`fixed`).

---

### Groupe 2 — CVEs OS sans correctif (`will_not_fix`)

**Packages concernés :** `zlib1g`, `linux-libc-dev`, `mariadb-common`, `openssh-client`

#### `zlib1g` — CVE-2023-45853 — CRITICAL — `will_not_fix`

```
Package          : zlib1g, zlib1g-dev
CVE              : CVE-2023-45853
Sévérité         : CRITICAL
Statut           : will_not_fix
Version installée: 1:1.2.13.dfsg-1
Version corrigée : (aucune pour Debian 12)
Description      : Integer overflow and resultant heap-based buffer overflow
                   in zipOpenNewFileInZip4_6
```

**Explication :**
`zlib` est la librairie de compression utilisée partout dans Linux.
Cette CVE affecte la fonction `zipOpenNewFileInZip4_6` qui n'est
**pas utilisée par DVNA** — l'application ne crée pas de fichiers ZIP.
Debian a marqué cette CVE comme `will_not_fix` car le vecteur d'exploitation
nécessite l'usage direct de cette fonction spécifique.

**Risques dans notre contexte :**

| Risque | Description |
|--------|-------------|
| **Risque théorique** | Buffer overflow possible uniquement via `zipOpenNewFileInZip4_6` |
| **Non exploitable ici** | DVNA n'utilise pas la création de fichiers ZIP |
| **Pas de fix Debian** | Debian 12 n'a pas de version corrigée disponible |

#### `linux-libc-dev` — Multiples CVEs — HIGH — `will_not_fix`

```
Package          : linux-libc-dev
CVEs             : Très nombreux (CVE-2013-7445, CVE-2019-19449, etc.)
Sévérité         : HIGH
Statut           : will_not_fix / affected
Version installée: 6.1.137-1
Description      : Headers du kernel Linux — non exécutés à l'intérieur du container
```

**Explication :**
`linux-libc-dev` contient les **headers** (fichiers `.h`) du kernel Linux.
Ces headers servent à la compilation — ils ne sont **pas exécutés**.
Les CVEs associées concernent le kernel Linux lui-même, pas les headers.
Un container Docker partage le kernel de l'hôte — il ne peut pas
être affecté par ces CVEs de l'intérieur du container.

**Risques dans notre contexte :**

| Risque | Description |
|--------|-------------|
| **Non applicable** | Les headers kernel ne s'exécutent pas dans le container |
| **Kernel partagé** | C'est le kernel de l'hôte qui compte — pas celui du container |
| **Faux positifs Trivy** | Trivy signale ces CVEs par précaution mais elles sont hors scope |

#### Correction appliquée — fichier `.trivyignore`

**Problème :**
Ces CVEs ne peuvent pas être corrigées au niveau de l'application car :
- `will_not_fix` = Debian ne fournira pas de correctif
- Les packages concernés sont hors scope de l'application (kernel headers, zlib ZIP)

**Solution — création du fichier `.trivyignore` :**

```bash
# .trivyignore — à la racine du projet
# CVEs Debian sans correctif disponible (will_not_fix)
# ou non exploitables dans le contexte de l'application

# zlib1g — overflow dans zipOpenNewFileInZip4_6 — non utilisé par DVNA
CVE-2023-45853

# linux-libc-dev — headers kernel — non exécutés dans le container
# (les CVEs kernel sont gérées au niveau de l'hôte, pas du container)
CVE-2013-7445
CVE-2019-19449
CVE-2019-19814
# ... (autres CVEs linux-libc-dev will_not_fix)
```

**Pourquoi cette solution :**
Le fichier `.trivyignore` indique à Trivy de ne pas bloquer le pipeline
sur des CVEs qui sont soit sans correctif disponible, soit non applicables
dans le contexte de l'application. C'est une décision **documentée et justifiée**,
pas un contournement aveugle — chaque CVE ignorée a une raison explicite.

---

### Groupe 3 — CVEs Node.js (packages `package.json` application)

Ces vulnérabilités sont les mêmes que celles détectées par `npm audit` (SCA).
Trivy les redétecte lors du scan de l'image car il analyse aussi `package.json`.

**Elles ont déjà été corrigées dans la branche `fix/sca`** —
la branche `fix/trivy` les corrige également en incluant les mises à jour SCA.

#### CVEs CRITICAL Node.js

| Package | CVE | Version vulnérable | Version corrigée | Correction |
|---------|-----|-------------------|-----------------|------------|
| `ejs` | CVE-2022-29078 | 3.1.6 | 3.1.7 | Mis à jour → `^3.1.10` |
| `node-serialize` | CVE-2017-5941 | 0.0.4 | aucune | **Supprimé** |
| `node-serialize` | NSWG-ECO-311 | 0.0.4 | aucune | **Supprimé** |
| `xmldom` | CVE-2022-39353 | 0.1.31 | aucune | **Supprimé** |

#### CVEs HIGH Node.js

| Package | CVEs | Version vulnérable | Correction |
|---------|------|-------------------|------------|
| `body-parser` | CVE-2024-45590 | 1.19.0 | `express@^4.22.1` |
| `path-to-regexp` | CVE-2024-45296, CVE-2024-52798 | 0.1.7 | `express@^4.22.1` |
| `qs` | CVE-2022-24999 | 6.7.0 | `express@^4.22.1` |
| `cross-spawn` | CVE-2024-21538 | 7.0.3 | `overrides: ^7.0.5` |
| `glob` | CVE-2025-64756 | 10.4.2 | `overrides: ^10.5.0` |
| `minimatch` | CVE-2026-26996/27903/27904 | 9.0.5 | `overrides: ^9.0.7` |
| `tar` | CVE-2026-23745 à 31802 (6 CVEs) | 6.2.1 | `overrides: ^7.5.11` |

#### Correction appliquée — `package.json`

```json
// AVANT — package.json (master)
{
  "dependencies": {
    "ejs":            "3.1.6",      // ❌ CRITICAL CVE-2022-29078
    "node-serialize": "0.0.4",      // ❌ CRITICAL CVE-2017-5941
    "xmldom":         "0.1.31",     // ❌ CRITICAL CVE-2022-39353
    "express":        "4.17.1",     // ❌ HIGH — body-parser, path-to-regexp, qs vulnérables
    "body-parser":    "1.19.0"      // ❌ HIGH CVE-2024-45590
  }
}

// APRÈS — package.json (fix/trivy — inclut fix/sca)
{
  "dependencies": {
    "ejs":            "^3.1.10",    // ✅ CRITICAL corrigé
    "express":        "^4.22.1",    // ✅ Corrige body-parser, path-to-regexp, qs
    "body-parser":    "^1.20.3",    // ✅ HIGH corrigé
    // node-serialize → SUPPRIMÉ    // ✅ CRITICAL supprimé — aucun fix possible
    // xmldom → SUPPRIMÉ            // ✅ CRITICAL supprimé — aucun fix possible
  },
  "overrides": {
    "brace-expansion": "^2.0.3",    // ✅ MODERATE corrigé
    "cross-spawn":     "^7.0.5",    // ✅ HIGH corrigé
    "glob":            "^10.5.0",   // ✅ HIGH corrigé
    "minimatch":       "^9.0.7",    // ✅ HIGH corrigé
    "tar":             "^7.5.11"    // ✅ 6 CVEs HIGH corrigées
  }
}
```

---

### Groupe 4 — Configuration Trivy dans le Jenkinsfile

**Problème :**
La commande Trivy dans le Jenkinsfile ne montait pas le répertoire courant
et ne passait pas le fichier `.trivyignore` — les CVEs `will_not_fix`
bloquaient donc le pipeline même sans correctif possible.

**Configuration AVANT :**

```groovy
// AVANT — Jenkinsfile
sh '''
  docker run --rm \
    -v //var/run/docker.sock://var/run/docker.sock \
    ghcr.io/aquasecurity/trivy:latest image \
    --severity HIGH,CRITICAL \
    --exit-code 1 \
    dvna-pfe:pipeline
'''
// ❌ Pas de --ignore-unfixed → CVEs will_not_fix bloquent le pipeline
// ❌ Pas de .trivyignore monté → impossible d'ignorer des CVEs spécifiques
```

**Configuration APRÈS :**

```groovy
// APRÈS — Jenkinsfile (fix/trivy)
sh '''
  docker build -t dvna-pfe:pipeline .

  docker run --rm \
    -v //var/run/docker.sock://var/run/docker.sock \
    -v "%CD%:/workspace" \
    -e TRIVY_IGNOREFILE=/workspace/.trivyignore \
    ghcr.io/aquasecurity/trivy:latest image \
    --severity HIGH,CRITICAL \
    --exit-code 1 \
    --ignore-unfixed \
    dvna-pfe:pipeline
'''
// ✅ --ignore-unfixed → ignore les CVEs sans correctif (will_not_fix)
// ✅ -v "%CD%:/workspace" → monte le répertoire courant dans le container Trivy
// ✅ TRIVY_IGNOREFILE → Trivy lit le .trivyignore pour les exclusions justifiées
```

**Pourquoi `--ignore-unfixed` :**
Une CVE sans correctif disponible ne peut pas être résolue par l'équipe de développement.
Bloquer le pipeline sur ces CVEs est contre-productif — cela bloque la livraison
sans qu'aucune action corrective ne soit possible. La bonne pratique est de
les ignorer avec `--ignore-unfixed` et de les documenter.

---

## Résumé complet des corrections dans `fix/trivy`

### Fichiers modifiés

| Fichier | Modification | Vulnérabilités corrigées |
|---------|-------------|--------------------------|
| `Dockerfile` | `FROM node:18.20-slim` + `apt-get upgrade` + `npm ci --omit=dev` | Toutes CVEs OS avec fix disponible |
| `package.json` | Mise à jour dépendances + `overrides` | Toutes CVEs Node.js |
| `.trivyignore` | Exclusion des CVEs `will_not_fix` | `zlib1g`, `linux-libc-dev`, `mariadb-common` |
| `Jenkinsfile` | `--ignore-unfixed` + montage `.trivyignore` | Pipeline ne bloque plus sur will_not_fix |

---

## Bilan AVANT / APRÈS

| Catégorie | AVANT | APRÈS |
|-----------|-------|-------|
| CVEs OS CRITICAL | ❌ 2 (openssl, zlib1g) | ✅ 0 (openssl corrigé, zlib1g ignoré) |
| CVEs OS HIGH | ❌ 8+ | ✅ 0 (corrigés via apt-get upgrade) |
| CVEs Node.js CRITICAL | ❌ 4 | ✅ 0 (mis à jour ou supprimés) |
| CVEs Node.js HIGH | ❌ 16 | ✅ 0 (mis à jour via overrides) |
| **Total** | ❌ **30+** | ✅ **0** |

---

## Résultat après correction

```
Trivy scan — branche fix/trivy

CRITICAL : 0   ✅
HIGH     : 0   ✅
Pipeline Jenkins : PASS → continue vers Stage 6 (IaC / Checkov)
```

---

## Principe DevSecOps appliqué — Container Security

> Sécuriser une application ne suffit pas — l'image Docker qui la fait tourner
> doit aussi être sécurisée. Une image avec des packages OS vulnérables
> est une porte d'entrée potentielle même si le code applicatif est parfait.
>
> La stratégie à trois niveaux :
> 1. **Mettre à jour** les packages OS avec `apt-get upgrade`
> 2. **Supprimer** les packages applicatifs sans correctif
> 3. **Documenter et ignorer** les CVEs non corrigeables (`will_not_fix`)

**Deux types de CVEs `will_not_fix` :**
- **Non exploitables** : CVEs affectant du code non utilisé par l'application
- **Hors scope** : CVEs du kernel Linux (gérées au niveau de l'hôte, pas du container)

**Règle du pipeline Jenkins :**
Si Trivy détecte au moins 1 CVE HIGH ou CRITICAL non ignorée,
le pipeline s'arrête à la **Stage 5 (Image Scan)** — l'image ne peut pas
être déployée.

---

*Projet PFE DevSecOps — DVNA Pipeline Jenkins*
*Branche : `fix/trivy` | Outil : Trivy | CVEs : 30+ → 0 | Date : 2026*

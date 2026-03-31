# README — Branche `fix/checkov` : Corrections IaC Security (Checkov)

## Contexte

L'analyse IaC (Infrastructure as Code) a été réalisée avec **Checkov**
sur le fichier `Dockerfile` de DVNA (Damn Vulnerable Node Application).

Checkov analyse le `Dockerfile` **statiquement** — sans construire l'image —
pour détecter des mauvaises pratiques de configuration connues
pouvant créer des failles de sécurité au niveau de l'infrastructure.

**Résultat du scan :**
```
Outil     : bridgecrew/checkov:2.3.0
Fichier   : /workspace/Dockerfile
Passed    : 12
Failed    : 2
Skipped   : 0
```

Le pipeline Jenkins s'arrête dès qu'un check échoue —
la branche `fix/checkov` corrige les 2 failures.

---

## Les 2 failures Checkov — Rapport brut

```
Check: CKV_DOCKER_2 — FAILED
  "Ensure that HEALTHCHECK instructions have been added to container images"
  File: /workspace/Dockerfile:1-21

Check: CKV_DOCKER_3 — FAILED
  "Ensure that a user for the container has been created"
  File: /workspace/Dockerfile:1-21
```

---

## Dockerfile vulnérable — Tel que détecté par Checkov

Voici le contenu exact du `Dockerfile` que Checkov a analysé et sur lequel
il a signalé les 2 failures (lignes 1 à 21) :

```dockerfile
 1 | # DVNA-PFE — Dockerfile VULNERABLE (intentionnel)
 2 | # Cibles : Trivy (CVEs image), Checkov (misconfigurations)
 3 |
 4 | # VULN-Trivy : image non épinglée avec CVEs dans les paquets OS
 5 | FROM node:18
 6 |
 7 | # VULN-Checkov CKV_DOCKER_2 : pas de HEALTHCHECK
 8 | # VULN-Checkov CKV_DOCKER_8 : pas d'USER non-root (tourne en root)
 9 |
10 | WORKDIR /app
11 |
12 | COPY package*.json ./
13 | RUN npm install
14 |
15 | COPY . .
16 |
17 | EXPOSE 9090
18 |
19 | # Pas de USER -> tourne en root
20 | # Pas de HEALTHCHECK -> Checkov alerte
21 | CMD ["node", "server.js"]
```

---

## Détail des failures et corrections

---

### Failure 1 — `CKV_DOCKER_2`

**Fichier :** `Dockerfile` — **Lignes 1–21**
**Check :** `CKV_DOCKER_2`
**Guide :** https://docs.prismacloud.io/en/enterprise-edition/policy-reference/docker-policies/docker-policy-index/ensure-that-healthcheck-instructions-have-been-added-to-container-images

#### Message Checkov
> Ensure that HEALTHCHECK instructions have been added to container images.

#### Code vulnérable (lignes 1–21)

```dockerfile
# Dockerfile (master) — lignes 1-21
FROM node:18

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 9090
CMD ["node", "server.js"]
# ← Aucune instruction HEALTHCHECK dans tout le fichier
# ← Docker ne sait pas si l'application est réellement fonctionnelle
```

#### Explication

Sans instruction `HEALTHCHECK`, Docker et les orchestrateurs (Kubernetes,
Docker Swarm) n'ont **aucun moyen de savoir si l'application répond correctement**.
Un container peut avoir le statut `running` (processus Node.js actif)
alors que l'application est bloquée, en erreur, ou ne répond plus aux requêtes HTTP.
Docker se contente alors de surveiller si le processus est vivant —
pas si l'application est fonctionnelle.

#### Risques

| Risque | Description |
|--------|-------------|
| **Application silencieusement défaillante** | Le container est `running` mais l'application ne répond plus — aucune alerte n'est générée |
| **Pas de redémarrage automatique** | Sans HEALTHCHECK, les orchestrateurs ne redémarrent pas un container dont l'application est bloquée |
| **Indisponibilité non détectée** | En production, les utilisateurs voient des erreurs mais le système croit que tout va bien |
| **Pas de contrôle de démarrage** | Impossible de savoir si l'application a bien démarré avant de lui envoyer du trafic |

**Scénario concret :**
```
1. Container démarre → Node.js se lance → statut Docker : "running" ✅
2. L'application plante (erreur mémoire, bug) → le processus reste actif
3. Les requêtes HTTP reçoivent des erreurs 500
4. Docker voit le processus vivant → ne fait rien → pas d'alerte
5. Sans HEALTHCHECK → la défaillance n'est jamais détectée automatiquement
```

#### Correction appliquée dans `fix/checkov`

```dockerfile
# AVANT — Dockerfile (master)
# ← Pas de HEALTHCHECK → Checkov FAIL CKV_DOCKER_2
CMD ["node", "server.js"]

# APRÈS — Dockerfile (fix/checkov)
# Prérequis : curl doit être installé dans l'image pour le HEALTHCHECK
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# ...

# ✅ HEALTHCHECK ajouté — Checkov CKV_DOCKER_2 PASS
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:9090/ || exit 1

CMD ["node", "server.js"]
```

**Paramètres du HEALTHCHECK expliqués :**

| Paramètre | Valeur | Signification |
|-----------|--------|---------------|
| `--interval=30s` | 30 secondes | Vérifie l'état de l'application toutes les 30 secondes |
| `--timeout=5s` | 5 secondes | La vérification doit répondre en moins de 5 secondes |
| `--start-period=10s` | 10 secondes | Attend 10s après le démarrage avant de commencer les checks |
| `--retries=3` | 3 tentatives | 3 échecs consécutifs → container marqué `unhealthy` |
| `curl -f http://localhost:9090/` | Requête HTTP | Vérifie que l'application répond avec un code HTTP 2xx |
| `\|\| exit 1` | Échec | Si curl échoue → retourne 1 → Docker marque le container unhealthy |

**Pourquoi cette solution :**
`curl -f` envoie une requête HTTP GET à l'application et retourne
un code d'erreur si la réponse HTTP est >= 400 ou si la connexion échoue.
C'est la méthode standard pour vérifier qu'une application web est opérationnelle.
`curl` doit être installé dans l'image via `apt-get install curl`.

---

### Failure 2 — `CKV_DOCKER_3`

**Fichier :** `Dockerfile` — **Lignes 1–21**
**Check :** `CKV_DOCKER_3`
**Guide :** https://docs.prismacloud.io/en/enterprise-edition/policy-reference/docker-policies/docker-policy-index/ensure-that-a-user-for-the-container-has-been-created

#### Message Checkov
> Ensure that a user for the container has been created.

#### Code vulnérable (lignes 1–21)

```dockerfile
# Dockerfile (master) — lignes 1-21
FROM node:18

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 9090
# ← Aucune instruction USER dans tout le fichier
# ← Le container s'exécute en tant que root par défaut
CMD ["node", "server.js"]
```

#### Explication

Par défaut, quand aucune instruction `USER` n'est définie dans un Dockerfile,
Docker exécute tous les processus du container **en tant que `root` (uid=0)**.
Cela signifie que le processus Node.js qui fait tourner DVNA
dispose des privilèges root à l'intérieur du container.

Si un attaquant réussit à exécuter du code dans l'application
(via une faille RCE par exemple), il se retrouve avec les **droits root**
à l'intérieur du container. Selon la configuration de l'hôte,
cela peut faciliter une **évasion de container** (container escape)
pour compromettre l'hôte Docker.

#### Risques

| Risque | Description |
|--------|-------------|
| **Privilèges root inutiles** | L'application n'a pas besoin de root pour fonctionner — principe du moindre privilège violé |
| **Container Escape** | En cas de RCE, l'attaquant root dans le container peut tenter de sortir du container vers l'hôte |
| **Accès à tous les fichiers** | Root dans le container peut lire/modifier tous les fichiers de l'image |
| **Montages dangereux** | Si des volumes sont montés, root peut accéder à tout le système de fichiers hôte |
| **Amplification des vulnérabilités** | Toute faille de l'application devient automatiquement une faille root |

**Scénario d'attaque :**
```
1. Attaquant exploite la vulnérabilité RCE via node-serialize (CVE-2017-5941)
2. Il exécute du code dans le container → il est root (uid=0)
3. Il tente : mount /dev/sda1 /mnt → accès au système de fichiers hôte
4. Ou : docker.sock monté → contrôle total du daemon Docker de l'hôte
5. Container root = porte d'entrée vers l'hôte
```

#### Correction appliquée dans `fix/checkov`

```dockerfile
# AVANT — Dockerfile (master)
# ← Aucun USER défini → root par défaut → Checkov FAIL CKV_DOCKER_3
RUN npm install
COPY . .
EXPOSE 9090
CMD ["node", "server.js"]

# APRÈS — Dockerfile (fix/checkov)
RUN npm ci --omit=dev

COPY . .

# ✅ Changement de propriétaire du répertoire applicatif vers l'utilisateur node
RUN chown -R node:node /app

# ✅ Passage à l'utilisateur non-root "node" — Checkov CKV_DOCKER_3 PASS
USER node

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:9090/ || exit 1

CMD ["node", "server.js"]
```

**Pourquoi l'utilisateur `node` :**
L'image officielle `node:18.20-slim` inclut déjà un utilisateur système
nommé `node` (uid=1000) créé spécifiquement pour exécuter des applications Node.js.
Il dispose des droits suffisants pour lancer Node.js mais pas des privilèges root.
`chown -R node:node /app` est nécessaire car les fichiers ont été copiés
en tant que root — il faut transférer leur propriété à l'utilisateur `node`
avant de changer d'utilisateur, sinon Node.js ne peut pas les lire.

---

## Les 12 checks PASS — Pour référence

Ces checks étaient déjà respectés dans le Dockerfile de `master`
et continuent d'être respectés dans `fix/checkov` :

| Check | Description | Statut |
|-------|-------------|--------|
| `CKV_DOCKER_1` | Port 22 (SSH) non exposé | ✅ PASS |
| `CKV_DOCKER_5` | `apt-get update` non utilisé seul | ✅ PASS |
| `CKV_DOCKER_7` | Image de base avec tag non-latest (`node:18.20-slim`) | ✅ PASS |
| `CKV_DOCKER_9` | APT non utilisé de manière non sécurisée | ✅ PASS |
| `CKV_DOCKER_10` | `WORKDIR` défini avec chemin absolu (`/app`) | ✅ PASS |
| `CKV_DOCKER_11` | Alias FROM uniques (pas de multi-stage build ici) | ✅ PASS |
| `CKV2_DOCKER_1` | `sudo` non utilisé | ✅ PASS |
| `CKV2_DOCKER_2` | `curl` sans désactivation de validation certificat | ✅ PASS |
| `CKV2_DOCKER_3` | `wget` sans désactivation de validation certificat | ✅ PASS |
| `CKV2_DOCKER_4` | `pip` sans `--trusted-host` | ✅ PASS |
| `CKV2_DOCKER_5` | `PYTHONHTTPSVERIFY` non désactivé | ✅ PASS |
| `CKV2_DOCKER_6` | `NODE_TLS_REJECT_UNAUTHORIZED` non désactivé | ✅ PASS |

---

## Dockerfile complet — AVANT / APRÈS

```dockerfile
# ================================================================
# AVANT — Dockerfile (branche master)
# 2 failures Checkov : CKV_DOCKER_2 + CKV_DOCKER_3
# ================================================================

 1  # DVNA-PFE — Dockerfile VULNERABLE (intentionnel)
 2  # Cibles : Trivy (CVEs image), Checkov (misconfigurations)
 3
 4  # VULN-Trivy : image non épinglée avec CVEs dans les paquets OS
 5  FROM node:18
    # ❌ Tag "latest" implicite → CVEs OS non corrigées (fix/trivy)
 6
 7  # VULN-Checkov CKV_DOCKER_2 : pas de HEALTHCHECK
 8  # VULN-Checkov CKV_DOCKER_8 : pas d'USER non-root (tourne en root)
 9
10  WORKDIR /app
11
12  COPY package*.json ./
13  RUN npm install
    # ❌ npm install installe les devDependencies → surface d'attaque plus large
14
15  COPY . .
16
17  EXPOSE 9090
18
19  # Pas de USER -> tourne en root
20  # ❌ CKV_DOCKER_3 : aucun USER défini → processus Node.js tourne en root
21  CMD ["node", "server.js"]
    # ❌ CKV_DOCKER_2 : aucun HEALTHCHECK → Docker ne sait pas si l'app répond
```

```dockerfile
# ================================================================
# APRÈS — Dockerfile (branche fix/checkov)
# 0 failure Checkov : tous les checks PASS
# ================================================================

FROM node:18.20-slim
# ✅ Version épinglée → comportement reproductible
# ✅ Image slim → surface d'attaque réduite

RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
# ✅ Packages OS mis à jour → CVEs OS corrigées (fix/trivy)
# ✅ curl installé → nécessaire pour le HEALTHCHECK
# ✅ --no-install-recommends → image plus légère
# ✅ rm -rf /var/lib/apt/lists/* → cache APT supprimé → image plus petite

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev
# ✅ npm ci → installation stricte et reproductible
# ✅ --omit=dev → pas de devDependencies → moins de packages vulnérables

COPY . .

RUN chown -R node:node /app
# ✅ Propriété des fichiers transférée à l'utilisateur node

USER node
# ✅ CKV_DOCKER_3 PASS : processus Node.js ne tourne plus en root

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:9090/ || exit 1
# ✅ CKV_DOCKER_2 PASS : Docker vérifie que l'application répond toutes les 30s

CMD ["node", "server.js"]
```

---

## Bilan complet — 2 failures AVANT / APRÈS

| # | Check | Ligne(s) | Problème | Risque principal | Correction |
|---|-------|----------|----------|-----------------|------------|
| 1 | `CKV_DOCKER_2` | 1–21 | Pas de `HEALTHCHECK` | Application défaillante non détectée | `HEALTHCHECK CMD curl -f http://localhost:9090/` |
| 2 | `CKV_DOCKER_3` | 1–21 | Pas d'instruction `USER` — tourne en root | Container Escape si RCE exploitée | `USER node` + `chown -R node:node /app` |

---

## Résultat après correction

```
Checkov scan — branche fix/checkov

Passed checks : 14   ✅  (12 déjà passés + 2 nouvellement corrigés)
Failed checks :  0   ✅
Pipeline Jenkins : PASS → continue vers Stage 7 (DAST / ZAP)
```

---

## Principe DevSecOps appliqué — Infrastructure as Code Security

> La sécurité ne concerne pas uniquement le code applicatif —
> la **configuration de l'infrastructure** (Dockerfile, docker-compose,
> Kubernetes manifests, Terraform...) doit aussi être auditée.
>
> Checkov applique le **principe du moindre privilège** :
> un container n'a besoin que des droits strictement nécessaires
> pour fonctionner — pas de root, pas de ports inutiles, pas de sudo.

**Les deux corrections en résumé :**
- **HEALTHCHECK** → permet à Docker de savoir si l'application est vivante
  et fonctionnelle, pas seulement si le processus est actif
- **USER non-root** → si l'application est compromise (RCE),
  l'attaquant ne se retrouve pas avec les droits root dans le container

**Règle du pipeline Jenkins :**
Si Checkov détecte au moins 1 check en échec sur le Dockerfile,
le pipeline s'arrête à la **Stage 6 (IaC Security)** — l'image ne peut pas
être déployée vers l'étape DAST.

---

*Projet PFE DevSecOps — DVNA Pipeline Jenkins*
*Branche : `fix/checkov` | Outil : Checkov 2.3.0 | Failed : 2 → 0 | Date : 2026*

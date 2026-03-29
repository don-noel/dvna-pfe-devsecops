# fix/checkov — Corrections des vulnérabilités IaC Security (Checkov)

## Contexte

Cette branche corrige les misconfigurations détectées par **Checkov** (Stage 5 du pipeline DevSecOps) sur le fichier `Dockerfile`.

Checkov analyse le Dockerfile statiquement pour détecter des mauvaises pratiques de sécurité dans la configuration de l'infrastructure.

---

## Vulnérabilités détectées (avant correction)

| Check | Description | Statut avant |
|---|---|---|
| CKV_DOCKER_5 | `apt-get update` utilisé seul sans `apt-get install` | ❌ FAIL |
| CKV_DOCKER_2 | Aucune instruction `HEALTHCHECK` dans l'image | ❌ FAIL |
| CKV_DOCKER_3 | Le container tourne en tant que `root` (pas d'instruction `USER`) | ❌ FAIL |

---

## Corrections apportées

### 1. CKV_DOCKER_5 — Combiner `apt-get update` et `apt-get install`

**Problème :** Checkov détecte un `apt-get update` isolé comme une mauvaise pratique car il peut entraîner des problèmes de cache Docker. La règle exige que `update` soit toujours combiné avec `install` dans la même instruction `RUN`.

**Solution :** Ajout de `apt-get install -y curl` (nécessaire pour le HEALTHCHECK) dans la même instruction `RUN` que le `update`.

```dockerfile
# AVANT (CKV_DOCKER_5 fail) :
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# APRÈS (CKV_DOCKER_5 pass) :
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*
```

**Bénéfice :** `curl` est installé proprement et utilisé par le HEALTHCHECK. Le flag `--no-install-recommends` minimise la taille de l'image en évitant les packages inutiles.

---

### 2. CKV_DOCKER_2 — Ajout d'un HEALTHCHECK

**Problème :** Sans `HEALTHCHECK`, Docker et les orchestrateurs (Kubernetes, Docker Swarm) ne peuvent pas détecter si l'application est réellement fonctionnelle. Un container peut être "running" mais l'application peut être bloquée ou en erreur.

**Solution :** Ajout d'une instruction `HEALTHCHECK` qui interroge l'endpoint principal de l'application toutes les 30 secondes.

```dockerfile
# CORRECTION CKV_DOCKER_2 : HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:9090/ || exit 1
```

**Paramètres expliqués :**
- `--interval=30s` : vérifie l'état toutes les 30 secondes
- `--timeout=5s` : la vérification doit répondre en moins de 5 secondes
- `--start-period=10s` : attend 10 secondes après le démarrage avant de commencer les vérifications
- `--retries=3` : 3 échecs consécutifs marquent le container comme `unhealthy`

---

### 3. CKV_DOCKER_3 — Exécution en utilisateur non-root

**Problème :** Par défaut, les containers Docker s'exécutent en tant que `root`. Si l'application est compromise, l'attaquant dispose des privilèges root dans le container, facilitant les attaques de type container escape.

**Solution :** Changement de propriétaire du répertoire `/app` vers l'utilisateur `node` (présent dans les images Node.js officielles), puis passage à cet utilisateur avec `USER node`.

```dockerfile
# CORRECTION CKV_DOCKER_3 : USER non-root
RUN chown -R node:node /app
USER node
```

**Pourquoi `node` ?** L'image `node:18.20-slim` inclut déjà un utilisateur système `node` avec les droits minimaux nécessaires pour exécuter une application Node.js.

---

## Dockerfile final (après corrections)

```dockerfile
# DVNA-PFE — Dockerfile CORRIGE (fix/checkov)
FROM node:18.20-slim

# CORRECTION CKV_DOCKER_5 : combine update + install dans une seule instruction
# curl est nécessaire pour le HEALTHCHECK
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev

COPY . .

# CORRECTION CKV_DOCKER_3 : USER non-root
RUN chown -R node:node /app
USER node

EXPOSE 9090

# CORRECTION CKV_DOCKER_2 : HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:9090/ || exit 1

CMD ["node", "server.js"]
```

---

## Résultat final

| Check | Description | Avant | Après |
|---|---|---|---|
| CKV_DOCKER_5 | apt-get update seul | ❌ FAIL | ✅ PASS |
| CKV_DOCKER_2 | HEALTHCHECK manquant | ❌ FAIL | ✅ PASS |
| CKV_DOCKER_3 | USER non-root absent | ❌ FAIL | ✅ PASS |
| Tous les autres checks | 17 checks déjà passés | ✅ PASS | ✅ PASS |
| **Total** | **27 checks** | **3 fail** | **0 fail** |
| **Stage 5 Checkov** | | ❌ FAIL | ✅ PASS |

---

## Prochaines étapes

- **`fix/zap`** — Corriger les alertes OWASP ZAP (headers de sécurité HTTP, CSP, cookies HttpOnly, X-Powered-By)

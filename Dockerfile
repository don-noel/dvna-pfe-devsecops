# DVNA-PFE — Dockerfile CORRIGE (fix/checkov)
FROM node:18.20-slim

# CORRECTION CKV_DOCKER_5 : combine update + install dans une seule instruction
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

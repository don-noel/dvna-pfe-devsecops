# DVNA-PFE — Dockerfile CORRIGE (fix/trivy)
# CORRECTION Trivy : image de base allégée avec moins de CVEs OS

# CORRECTION CKV_DOCKER_7 : image épinglée avec tag précis
# CORRECTION Trivy : node:18-slim réduit la surface d'attaque OS
FROM node:18.20-slim

WORKDIR /app

COPY package*.json ./

# CORRECTION Trivy : npm ci plus strict que npm install
RUN npm ci --omit=dev

COPY . .

EXPOSE 9090

CMD ["node", "server.js"]

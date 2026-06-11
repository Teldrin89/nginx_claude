FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src/ ./src/
COPY scripts/ ./scripts/

# Generate RSA keys at build time (override with a volume mount for persistent keys)
RUN node scripts/generate-keys.js

ENV PORT=3000
ENV NODE_ENV=development

EXPOSE 3000

CMD ["node", "src/server.js"]

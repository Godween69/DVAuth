# DV Auth: образ сервиса. Зависимость одна (pg), сборки нет.
# Сборка: docker build -t dvauth:latest .
FROM node:22.23.1-alpine
ENV NODE_ENV=production DVAUTH_HOST=0.0.0.0 DVAUTH_INTERNAL_HOST=0.0.0.0
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY src src
COPY migrations migrations
USER node
EXPOSE 3010 3011
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:3010/health || exit 1
# Сначала миграции базы, потом сервис.
CMD ["sh", "-c", "node src/migrate-cli.js && exec node src/main.js"]

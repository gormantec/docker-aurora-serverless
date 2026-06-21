# docker-aurora-serverless
# SQLite-backed MySQL wire protocol proxy
# Looks like Amazon Aurora Serverless to any MySQL client

FROM node:20-alpine

# Install SQLite (for direct DB inspection/debugging)
RUN apk add --no-cache sqlite

# Create data directory for SQLite databases
RUN mkdir -p /data && chmod 777 /data

WORKDIR /usr/src/app

# Install dependencies
COPY package.json ./
RUN npm install --production

# Copy proxy source
COPY src/ ./src/

# Environment variables — non-sensitive defaults only
# AURORA_PASSWORD must be set at runtime (no default — security requirement)
ENV AURORA_USER=admin
ENV AURORA_PORT=3306
ENV DATA_DIR=/data
ENV DEFAULT_DATABASE=aurora

# Expose MySQL wire protocol port
EXPOSE 3306

# Entrypoint: validate required vars, init default DB, start proxy
ENTRYPOINT ["sh", "-c", "\
  if [ -z \"$AURORA_PASSWORD\" ]; then \
    AURORA_PASSWORD=$(tr -dc A-Za-z0-9 < /dev/urandom | head -c 32); \
    echo '[aurora] ⚠️  AURORA_PASSWORD not set — generated random password (visible in logs):'; \
    echo ''; \
    echo '    ┌─────────────────────────────────────────────────────┐'; \
    echo \"    │  AURORA_USER=admin                                  │\"; \
    printf '    │  AURORA_PASSWORD=%-32s  │\n' \"$AURORA_PASSWORD\"; \
    echo '    └─────────────────────────────────────────────────────┘'; \
    echo ''; \
  fi && \
  echo '[aurora] Initializing default database: ${DEFAULT_DATABASE}' && \
  sqlite3 ${DATA_DIR}/${DEFAULT_DATABASE}.sqlite 'CREATE TABLE IF NOT EXISTS _aurora_init (initialized_at TEXT);' 2>/dev/null; \
  echo '[aurora] Starting MySQL wire protocol proxy on port ${AURORA_PORT}' && \
  exec node src/server.mjs \
"]

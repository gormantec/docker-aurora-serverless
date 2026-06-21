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

# Environment variables with defaults
ENV AURORA_USER=admin
ENV AURORA_PASSWORD=password
ENV AURORA_PORT=3306
ENV DATA_DIR=/data
ENV DEFAULT_DATABASE=aurora

# Expose MySQL wire protocol port
EXPOSE 3306

# Create default database on startup, then run proxy
ENTRYPOINT ["sh", "-c", "\
  echo '[aurora] Initializing default database: ${DEFAULT_DATABASE}' && \
  sqlite3 ${DATA_DIR}/${DEFAULT_DATABASE}.sqlite 'CREATE TABLE IF NOT EXISTS _aurora_init (initialized_at TEXT);' 2>/dev/null; \
  echo '[aurora] Starting MySQL wire protocol proxy on port ${AURORA_PORT}' && \
  exec node src/server.mjs \
"]

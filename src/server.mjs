/**
 * server.mjs — MySQL Wire Protocol Proxy
 *
 * Listens on port 3306, speaks the MySQL wire protocol, and translates
 * SQL queries to SQLite. Any MySQL client (mysql CLI, MySQL Workbench,
 * Node.js mysql2, Python mysql-connector, etc.) can connect.
 *
 * Implements enough of the MySQL protocol handshake and query cycle to
 * pass as an Amazon Aurora Serverless instance.
 */

import net from 'net';
import crypto from 'crypto';
import { Database } from './sqlite-engine.mjs';
import { MySQLHandshake, parseCommand, buildOK, buildERR, buildResultSet, buildEOF } from './protocol.mjs';

// ── Configuration ──────────────────────────────────────────────

const PORT = parseInt(process.env.AURORA_PORT || '3306', 10);
const USER = process.env.AURORA_USER || 'admin';
const PASSWORD = process.env.AURORA_PASSWORD || 'password';
const DATA_DIR = process.env.DATA_DIR || '/data';
const DEFAULT_DB = process.env.DEFAULT_DATABASE || 'aurora';

// Track per-connection state
const connections = new Map();

// ── SQLite Engine ──────────────────────────────────────────────

const engine = new Database(DATA_DIR);

// Ensure default database exists
engine.ensureDatabase(DEFAULT_DB);

// ── Connection Handler ─────────────────────────────────────────

const server = net.createServer((socket) => {
  const connId = crypto.randomUUID();
  const state = {
    id: connId,
    database: DEFAULT_DB,
    authenticated: false,
    sequenceId: 0,
  };
  connections.set(connId, state);

  console.log(`[aurora] Connection ${connId.slice(0, 8)} from ${socket.remoteAddress}`);

  // ── Send MySQL Handshake ──────────────────────────────────────
  const handshake = MySQLHandshake.create(connId);
  socket.write(handshake);

  let buffer = Buffer.alloc(0);

  socket.on('data', async (data) => {
    buffer = Buffer.concat([buffer, data]);

    // ── Handle handshake response ───────────────────────────────
    if (!state.authenticated) {
      const authResult = MySQLHandshake.verifyResponse(buffer, USER, PASSWORD);
      if (!authResult.valid) {
        socket.write(buildERR(2, "Access denied for user '" + USER + "'"));
        socket.end();
        return;
      }

      state.authenticated = true;
      state.sequenceId = authResult.sequenceId + 1;
      socket.write(buildOK(state.sequenceId++, 0, 0));
      console.log(`[aurora] Connection ${connId.slice(0, 8)} authenticated as ${USER}`);
      buffer = authResult.remaining || Buffer.alloc(0);
      if (buffer.length === 0) return;
      // Fall through to process any pipelined commands
    }

    // ── Process commands ────────────────────────────────────────
    while (buffer.length >= 4) {
      const payloadLength = buffer.readUInt24LE(0);
      const sequenceId = buffer.readUInt8(3);
      const totalLength = 4 + payloadLength;

      if (buffer.length < totalLength) break; // Need more data

      const payload = buffer.subarray(4, totalLength);
      buffer = buffer.subarray(totalLength);
      state.sequenceId = sequenceId + 1;

      try {
        const command = parseCommand(payload);
        const result = await executeCommand(command, state, engine);
        socket.write(result);
      } catch (err) {
        console.error(`[aurora] Command error:`, err.message);
        socket.write(buildERR(state.sequenceId++, err.message));
      }
    }
  });

  socket.on('close', () => {
    connections.delete(connId);
    console.log(`[aurora] Connection ${connId.slice(0, 8)} closed`);
  });

  socket.on('error', (err) => {
    console.error(`[aurora] Connection ${connId.slice(0, 8)} error:`, err.message);
    connections.delete(connId);
  });
});

// ── Command Executor ───────────────────────────────────────────

async function executeCommand(command, state, engine) {
  const seq = state.sequenceId++;

  switch (command.type) {
    case 'COM_QUERY': {
      const sql = command.sql.trim();

      // Handle USE <database>
      const useMatch = sql.match(/^USE\s+`?(\w+)`?\s*;?\s*$/i);
      if (useMatch) {
        const dbName = useMatch[1];
        engine.ensureDatabase(dbName);
        state.database = dbName;
        return buildOK(seq, 0, 0);
      }

      // Handle SHOW DATABASES
      if (/^SHOW\s+DATABASES/i.test(sql)) {
        const dbs = engine.listDatabases();
        const rows = dbs.map(name => [name]);
        const cols = [{ name: 'Database', type: 'VARCHAR' }];
        return buildResultSet(seq, cols, rows);
      }

      // Handle SHOW TABLES
      if (/^SHOW\s+(FULL\s+)?TABLES/i.test(sql)) {
        const tables = engine.listTables(state.database);
        const rows = tables.map(name => [name]);
        const cols = [{ name: `Tables_in_${state.database}`, type: 'VARCHAR' }];
        return buildResultSet(seq, cols, rows);
      }

      // Handle CREATE DATABASE
      const createDbMatch = sql.match(/^CREATE\s+(DATABASE|SCHEMA)\s+(IF\s+NOT\s+EXISTS\s+)?`?(\w+)`?\s*;?\s*$/i);
      if (createDbMatch) {
        const dbName = createDbMatch[3];
        engine.createDatabase(dbName);
        return buildOK(seq, 0, 0);
      }

      // Handle SELECT (result set)
      if (/^\s*(SELECT|DESCRIBE|EXPLAIN|SHOW\s+COLUMNS|SHOW\s+INDEX|SHOW\s+CREATE|SHOW\s+STATUS|SHOW\s+VARIABLES|WITH)\b/i.test(sql)) {
        const { columns, rows } = engine.query(state.database, sql);
        // SHOW VARIABLES / SHOW STATUS → add Aurora-specific stubs
        if (/^SHOW\s+VARIABLES/i.test(sql)) {
          rows.push(['aurora_version', '5.7.mysql_aurora.2.11.3']);
          rows.push(['aurora_serverless', 'ON']);
        }
        if (/^SHOW\s+STATUS/i.test(sql)) {
          rows.push(['Aurora_serverless', 'ON']);
        }
        return buildResultSet(seq, columns, rows);
      }

      // Handle other statements (INSERT, UPDATE, DELETE, CREATE TABLE, etc.)
      const { changes, lastInsertRowid } = engine.execute(state.database, sql);
      return buildOK(seq, changes, lastInsertRowid);
    }

    case 'COM_INIT_DB': {
      // USE <database> via COM_INIT_DB
      const dbName = command.database;
      engine.ensureDatabase(dbName);
      state.database = dbName;
      return buildOK(seq, 0, 0);
    }

    case 'COM_PING':
      return buildOK(seq, 0, 0);

    case 'COM_QUIT':
      // Connection will be closed by the socket handler
      return Buffer.alloc(0);

    case 'COM_STMT_PREPARE':
      // Prepared statement — store and return stmt ID
      // For now, we don't support full prepared statement protocol
      return buildERR(seq, 'Prepared statements not yet supported');

    default:
      return buildERR(seq, `Unknown command: 0x${command.type.toString(16)}`);
  }
}

// ── Start ──────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`[aurora] Aurora Serverless proxy listening on port ${PORT}`);
  console.log(`[aurora] Data directory: ${DATA_DIR}`);
  console.log(`[aurora] Default database: ${DEFAULT_DB}`);
  console.log(`[aurora] Connect: mysql -h 127.0.0.1 -P ${PORT} -u ${USER} -p${PASSWORD} ${DEFAULT_DB}`);
});

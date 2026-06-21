/**
 * protocol.mjs — MySQL Wire Protocol Builder/Parser
 *
 * Implements a subset of the MySQL client/server protocol sufficient
 * for basic query execution. Handles:
 *   - Initial handshake packet (server → client)
 *   - Handshake response (client → server)
 *   - Command packets: COM_QUERY, COM_INIT_DB, COM_PING, COM_QUIT
 *   - Response packets: OK, ERR, ResultSet (column count → column defs → rows → EOF)
 *
 * Ref: https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
 */

import crypto from 'crypto';

// ── Constants ──────────────────────────────────────────────────

// Protocol versions
const PROTOCOL_VERSION = 10;

// Server status flags
const SERVER_STATUS_AUTOCOMMIT = 0x0002;

// Client capability flags (what we advertise)
const CLIENT_LONG_PASSWORD = 0x00000001;
const CLIENT_FOUND_ROWS = 0x00000002;
const CLIENT_LONG_FLAG = 0x00000004;
const CLIENT_CONNECT_WITH_DB = 0x00000008;
const CLIENT_PROTOCOL_41 = 0x00000200;
const CLIENT_TRANSACTIONS = 0x00002000;
const CLIENT_SECURE_CONNECTION = 0x00008000;
const CLIENT_PLUGIN_AUTH = 0x00080000;

const CAPABILITY_FLAGS =
  CLIENT_LONG_PASSWORD |
  CLIENT_FOUND_ROWS |
  CLIENT_LONG_FLAG |
  CLIENT_CONNECT_WITH_DB |
  CLIENT_PROTOCOL_41 |
  CLIENT_TRANSACTIONS |
  CLIENT_SECURE_CONNECTION |
  CLIENT_PLUGIN_AUTH;

// Auth plugin
const AUTH_PLUGIN = 'mysql_native_password';

// Character set: utf8mb4_general_ci
const CHARSET = 45; // utf8mb4

// ── Handshake Packet Builder ──────────────────────────────────

export class MySQLHandshake {
  /**
   * Create the initial handshake packet (server → client).
   * Returns a Buffer the server sends immediately upon connection.
   */
  static create(connectionId) {
    const authData = crypto.randomBytes(20);
    // First 8 bytes + second 12 bytes (for secure connection)
    const authData1 = authData.subarray(0, 8);
    const authData2 = authData.subarray(8, 20);

    const buf = Buffer.alloc(256);
    let offset = 0;

    // Protocol version
    buf.writeUInt8(PROTOCOL_VERSION, offset); offset += 1;

    // Server version string (null-terminated)
    const serverVersion = '5.7.mysql_aurora.2.11.3';
    offset += buf.write(serverVersion, offset, 'utf8');
    buf.writeUInt8(0, offset); offset += 1;

    // Connection ID (4 bytes)
    buf.writeUInt32LE(connectionId, offset); offset += 4;

    // Auth data part 1 (8 bytes)
    authData1.copy(buf, offset); offset += 8;

    // Filler (1 byte)
    buf.writeUInt8(0, offset); offset += 1;

    // Capability flags (lower 2 bytes)
    buf.writeUInt16LE(CAPABILITY_FLAGS & 0xFFFF, offset); offset += 2;

    // Character set (1 byte)
    buf.writeUInt8(CHARSET, offset); offset += 1;

    // Server status flags (2 bytes)
    buf.writeUInt16LE(SERVER_STATUS_AUTOCOMMIT, offset); offset += 2;

    // Capability flags (upper 2 bytes)
    buf.writeUInt16LE((CAPABILITY_FLAGS >> 16) & 0xFFFF, offset); offset += 2;

    // Auth data length (1 byte) — always 21 for mysql_native_password
    buf.writeUInt8(21, offset); offset += 1;

    // Reserved (10 bytes)
    buf.fill(0, offset, offset + 10); offset += 10;

    // Auth data part 2 (12 bytes, padded to 13 with null)
    authData2.copy(buf, offset); offset += 12;
    buf.writeUInt8(0, offset); offset += 1;

    // Auth plugin name (null-terminated)
    offset += buf.write(AUTH_PLUGIN, offset, 'utf8');
    buf.writeUInt8(0, offset); offset += 1;

    const payload = buf.subarray(0, offset);

    // Wrap in MySQL packet header (3-byte length + 1-byte sequence ID)
    const packet = Buffer.alloc(4 + payload.length);
    packet.writeUInt24LE(payload.length, 0);
    packet.writeUInt8(0, 3); // Sequence ID 0
    payload.copy(packet, 4);

    // Store auth data for verification
    (packet)._authData = authData;

    return packet;
  }

  /**
   * Verify the handshake response from the client.
   * Returns { valid, sequenceId, remaining } or { valid: false }.
   */
  static verifyResponse(buffer, expectedUser, expectedPassword) {
    if (buffer.length < 4) return { valid: false };

    const payloadLength = buffer.readUInt24LE(0);
    const sequenceId = buffer.readUInt8(3);
    if (buffer.length < 4 + payloadLength) return { valid: false };

    const payload = buffer.subarray(4, 4 + payloadLength);
    const remaining = buffer.subarray(4 + payloadLength);

    // Parse handshake response
    let offset = 0;
    const clientCapability = payload.readUInt32LE(offset); offset += 4;
    const maxPacketSize = payload.readUInt32LE(offset); offset += 4;
    const charset = payload.readUInt8(offset); offset += 1;

    // Reserved 23 bytes
    offset += 23;

    // Username (null-terminated)
    let username = '';
    while (offset < payload.length && payload[offset] !== 0) {
      username += String.fromCharCode(payload[offset]);
      offset += 1;
    }
    offset += 1; // Skip null

    // Auth response length (1 byte if CLIENT_SECURE_CONNECTION, else auth is null-terminated)
    let authResponse;
    if (clientCapability & CLIENT_SECURE_CONNECTION) {
      const authLen = payload.readUInt8(offset); offset += 1;
      authResponse = payload.subarray(offset, offset + authLen);
      offset += authLen;
    } else {
      const start = offset;
      while (offset < payload.length && payload[offset] !== 0) offset += 1;
      authResponse = payload.subarray(start, offset);
      offset += 1;
    }

    // Database name (if CLIENT_CONNECT_WITH_DB)
    let database = '';
    if (clientCapability & CLIENT_CONNECT_WITH_DB) {
      while (offset < payload.length && payload[offset] !== 0) {
        database += String.fromCharCode(payload[offset]);
        offset += 1;
      }
    }

    // Verify username (for now, accept any — docker-iot handles real auth at the API layer)
    const usernameMatch = username.length > 0;

    // Verify password hash
    // mysql_native_password: SHA1(password) XOR SHA1(authData + SHA1(SHA1(password)))
    const sha1 = (data) => crypto.createHash('sha1').update(data).digest();
    const passwordHash = sha1(Buffer.from(expectedPassword, 'utf8'));
    const doubleHash = sha1(passwordHash);
    const combined = Buffer.concat([(this._handshakeAuthData || Buffer.alloc(20)), doubleHash]);
    const expectedAuth = Buffer.alloc(20);
    for (let i = 0; i < 20; i++) {
      expectedAuth[i] = passwordHash[i] ^ sha1(combined)[i];
    }

    const authMatch = authResponse && expectedAuth.equals(authResponse);

    if (!usernameMatch || !authMatch) {
      console.warn(`[mysql] Auth failed: user=${username}, auth_match=${authMatch}`);
      return { valid: false };
    }

    return {
      valid: true,
      sequenceId: sequenceId,
      remaining: remaining,
      username,
      database: database || 'aurora',
      clientCapability,
    };
  }
}

// ── Command Parser ─────────────────────────────────────────────

// Command types
const COM_SLEEP = 0x00;
const COM_QUIT = 0x01;
const COM_INIT_DB = 0x02;
const COM_QUERY = 0x03;
const COM_PING = 0x0E;
const COM_STMT_PREPARE = 0x16;
const COM_STMT_EXECUTE = 0x17;
const COM_STMT_CLOSE = 0x19;
const COM_RESET_CONNECTION = 0x1F;

export function parseCommand(payload) {
  if (payload.length === 0) return { type: 'UNKNOWN' };

  const type = payload[0];
  const data = payload.subarray(1);

  switch (type) {
    case COM_QUERY:
      return { type: 'COM_QUERY', sql: data.toString('utf8') };

    case COM_INIT_DB:
      return { type: 'COM_INIT_DB', database: data.toString('utf8') };

    case COM_PING:
      return { type: 'COM_PING' };

    case COM_QUIT:
      return { type: 'COM_QUIT' };

    case COM_STMT_PREPARE:
      return { type: 'COM_STMT_PREPARE', sql: data.toString('utf8') };

    case COM_STMT_EXECUTE:
      return { type: 'COM_STMT_EXECUTE', data };

    case COM_STMT_CLOSE:
      return { type: 'COM_STMT_CLOSE', stmtId: data.readUInt32LE(0) };

    case COM_RESET_CONNECTION:
      return { type: 'COM_RESET_CONNECTION' };

    default:
      return { type: 'UNKNOWN', code: type };
  }
}

// ── Response Packet Builders ──────────────────────────────────

/**
 * Build OK_Packet.
 * Used for: INSERT, UPDATE, DELETE, CREATE TABLE, USE, etc.
 */
export function buildOK(sequenceId, affectedRows = 0, lastInsertId = 0) {
  const statusFlags = SERVER_STATUS_AUTOCOMMIT;

  // Fixed: 1 (header) + varint affectedRows + varint lastInsertId
  //        + 2 (status) + 2 (warnings) = at least 7
  const affectedLen = lenencLength(affectedRows);
  const insertIdLen = lenencLength(lastInsertId);

  const payload = Buffer.alloc(7 + affectedLen + insertIdLen);
  let offset = 0;

  payload.writeUInt8(0x00, offset); offset += 1; // OK packet header
  offset = writeLenenc(payload, offset, affectedRows);
  offset = writeLenenc(payload, offset, lastInsertId);
  payload.writeUInt16LE(statusFlags, offset); offset += 2;
  payload.writeUInt16LE(0, offset); offset += 2; // Warnings

  return pack(sequenceId, payload.subarray(0, offset));
}

/**
 * Build ERR_Packet.
 */
export function buildERR(sequenceId, message) {
  const msg = Buffer.from(message, 'utf8');
  const payload = Buffer.alloc(9 + msg.length);
  let offset = 0;

  payload.writeUInt8(0xFF, offset); offset += 1; // ERR packet header
  payload.writeUInt16LE(0x0400, offset); offset += 2; // Error code (1040)
  payload.writeUInt8(0x23, offset); offset += 1; // SQL state marker '#'
  offset += payload.write('HY000', offset, 'utf8'); // SQL state
  msg.copy(payload, offset);

  return pack(sequenceId, payload);
}

/**
 * Build a result set response (SELECT).
 * Sequence:
 *   1. Column count packet
 *   2. Column definition packets (one per column)
 *   3. EOF packet (if CLIENT_DEPRECATE_EOF not set)
 *   4. Row data packets (one per row)
 *   5. EOF packet (final)
 */
export function buildResultSet(sequenceId, columns, rows) {
  let seq = sequenceId;
  const packets = [];

  // 1. Column count
  const colCountPayload = Buffer.alloc(1 + lenencLength(columns.length));
  let offset = colCountPayload.writeUInt8(columns.length, 0);
  // (col count is already written as first byte if < 251)
  packets.push(pack(seq++, colCountPayload.subarray(0, 1)));

  // 2. Column definitions
  for (const col of columns) {
    packets.push(buildColumnDefinition(seq++, col));
  }

  // 3. Intermediate EOF
  packets.push(buildEOF(seq++));

  // 4. Rows
  for (const row of rows) {
    packets.push(buildRow(seq++, row));
  }

  // 5. Final EOF
  packets.push(buildEOF(seq++));

  return Buffer.concat(packets);
}

function buildColumnDefinition(sequenceId, col) {
  // Simplified column definition packet
  const catalog = 'def';
  const schema = '';
  const table = '';
  const orgTable = '';
  const name = col.name;
  const orgName = col.name;

  const parts = [
    Buffer.from(catalog, 'utf8'),
    Buffer.from(schema, 'utf8'),
    Buffer.from(table, 'utf8'),
    Buffer.from(orgTable, 'utf8'),
    Buffer.from(name, 'utf8'),
    Buffer.from(orgName, 'utf8'),
  ];

  // Fixed fields: 1 (length of fixed fields) + 2 (charset) + 4 (col length) + 1 (type) + 2 (flags) + 1 (decimals) + 2 (filler)
  const fixedSize = 13;
  let totalLen = 0;
  for (const p of parts) totalLen += 1 + p.length; // lenenc prefix + data

  const payload = Buffer.alloc(totalLen + fixedSize);
  let offset = 0;

  for (const part of parts) {
    offset = writeLenenc(payload, offset, part.length);
    part.copy(payload, offset);
    offset += part.length;
  }

  // Next length (always 0x0C = 12 bytes of following data)
  payload.writeUInt8(0x0C, offset); offset += 1;

  // Character set (utf8mb4 = 45)
  payload.writeUInt16LE(45, offset); offset += 2;

  // Column length (max display width)
  payload.writeUInt32LE(255, offset); offset += 4;

  // Column type (MYSQL_TYPE_VARCHAR = 253 for strings, MYSQL_TYPE_LONGLONG = 8 for ints)
  const typeCode = mapColumnType(col.type);
  payload.writeUInt8(typeCode, offset); offset += 1;

  // Flags (NOT_NULL = 0x0001)
  payload.writeUInt16LE(0x0001, offset); offset += 2;

  // Decimals
  payload.writeUInt8(0x00, offset); offset += 1;

  // Filler
  payload.writeUInt16LE(0x0000, offset); offset += 2;

  return pack(sequenceId, payload);
}

function buildRow(sequenceId, values) {
  const parts = values.map(v => {
    if (v === null || v === undefined) return Buffer.from([0xFB]); // NULL
    const str = String(v);
    const buf = Buffer.from(str, 'utf8');
    const len = lenencLength(str.length);
    const header = Buffer.alloc(len);
    writeLenenc(header, 0, str.length);
    return Buffer.concat([header, buf]);
  });

  const payload = Buffer.concat(parts);
  return pack(sequenceId, payload);
}

export function buildEOF(sequenceId) {
  const payload = Buffer.alloc(5);
  payload.writeUInt8(0xFE, 0); // EOF header
  payload.writeUInt16LE(0x0002, 1); // Warnings
  payload.writeUInt16LE(SERVER_STATUS_AUTOCOMMIT, 3); // Status flags
  return pack(sequenceId, payload);
}

// ── Helpers ───────────────────────────────────────────────────

function pack(sequenceId, payload) {
  const header = Buffer.alloc(4);
  header.writeUInt24LE(payload.length, 0);
  header.writeUInt8(sequenceId, 3);
  return Buffer.concat([header, payload]);
}

function lenencLength(value) {
  if (value < 251) return 1;
  if (value < 65536) return 3;
  if (value < 16777216) return 4;
  return 9;
}

function writeLenenc(buf, offset, value) {
  if (value < 251) {
    buf.writeUInt8(value, offset);
    return offset + 1;
  }
  if (value < 65536) {
    buf.writeUInt8(0xFC, offset);
    buf.writeUInt16LE(value, offset + 1);
    return offset + 3;
  }
  if (value < 16777216) {
    buf.writeUInt8(0xFD, offset);
    buf.writeUInt24LE(value, offset + 1);
    return offset + 4;
  }
  buf.writeUInt8(0xFE, offset);
  buf.writeBigInt64LE(BigInt(value), offset + 1);
  return offset + 9;
}

function mapColumnType(typeName) {
  const t = (typeName || '').toUpperCase();
  if (t.includes('INT')) return 8;   // MYSQL_TYPE_LONGLONG
  if (t.includes('FLOAT') || t.includes('DOUBLE') || t.includes('REAL')) return 5; // MYSQL_TYPE_DOUBLE
  if (t.includes('BLOB')) return 252; // MYSQL_TYPE_BLOB
  if (t.includes('TEXT')) return 252;
  return 253; // MYSQL_TYPE_VARCHAR
}

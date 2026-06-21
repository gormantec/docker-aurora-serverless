/**
 * sqlite-engine.mjs — SQLite Database Engine
 *
 * Manages SQLite databases with optional AES-256-GCM encryption at rest.
 *
 * Without encryption: standard .sqlite files managed by better-sqlite3.
 * With encryption: the .sqlite file on disk is encrypted; better-sqlite3
 * works on a decrypted temp copy synced back after writes.
 *
 * Configure per-database encryption via Docker Swarm secrets:
 *   /run/secrets/aurora-key-<dbname>  (tmpfs, never on disk)
 *
 * Keys are created by the CloudFormation handler via docker secret create.
 * Source of truth: docker-iot Secrets Manager.
 */

import { Database as SQLiteDB } from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

export class Database {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this._dbs = new Map();        // dbName → SQLiteDB instance
    this._keys = new Map();       // dbName → encryption key
    this._tempPaths = new Map();  // dbName → temp file path
    this._dirty = new Set();      // dbNames needing re-encryption
    this._loadKeys();
  }

  _loadKeys() {
    // Read encryption keys from Docker Swarm secrets at /run/secrets/aurora-key-<dbname>
    // These are tmpfs mounts — never written to disk, never in env vars.
    // Also fall back to /data/.keys/<dbname> for non-Swarm setups.
    const sources = ['/run/secrets', path.join(this.dataDir, '.keys')];
    for (const dir of sources) {
      if (!fs.existsSync(dir)) continue;
      try {
        for (const file of fs.readdirSync(dir)) {
          const prefix = 'aurora-key-';
          if (!file.startsWith(prefix)) continue;
          const dbName = file.slice(prefix.length).toLowerCase();
          if (this._keys.has(dbName)) continue; // already loaded from a higher-priority source
          try {
            const key = fs.readFileSync(path.join(dir, file), 'utf-8').trim();
            if (key) this._keys.set(dbName, key);
          } catch { /* skip unreadable */ }
        }
      } catch { /* dir not accessible */ }
    }
  }

  _isEncrypted(dbName) { return this._keys.has(dbName); }
  _getKey(dbName) { return this._keys.get(dbName); }

  _deriveKeyBytes(key) {
    return crypto.createHash('sha256').update(key).digest();
  }

  _encrypt(plaintext, key) {
    const keyBytes = this._deriveKeyBytes(key);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, keyBytes, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return { iv, authTag, encrypted };
  }

  _decrypt(iv, authTag, encrypted, key) {
    const keyBytes = this._deriveKeyBytes(key);
    const decipher = crypto.createDecipheriv(ALGORITHM, keyBytes, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }

  _decryptToTemp(dbName) {
    const key = this._getKey(dbName);
    if (!key) throw new Error(`No encryption key for '${dbName}'`);

    const encPath = path.join(this.dataDir, `${dbName}.sqlite`);
    const raw = fs.readFileSync(encPath);

    const ivLen = raw.readUInt32LE(0);
    const iv = raw.subarray(4, 4 + ivLen);
    const authTag = raw.subarray(4 + ivLen, 4 + ivLen + AUTH_TAG_LENGTH);
    const encrypted = raw.subarray(4 + ivLen + AUTH_TAG_LENGTH);

    const decrypted = this._decrypt(iv, authTag, encrypted, key);
    const tempPath = path.join(os.tmpdir(), `${dbName}-${Date.now()}.sqlite`);
    fs.writeFileSync(tempPath, decrypted);
    this._tempPaths.set(dbName, tempPath);
    return tempPath;
  }

  _encryptToDisk(dbName) {
    const key = this._getKey(dbName);
    if (!key) return false;

    const tempPath = this._tempPaths.get(dbName);
    if (!tempPath || !fs.existsSync(tempPath)) return false;

    const plaintext = fs.readFileSync(tempPath);
    const { iv, authTag, encrypted } = this._encrypt(plaintext, key);

    const header = Buffer.alloc(4);
    header.writeUInt32LE(iv.length, 0);
    const out = Buffer.concat([header, iv, authTag, encrypted]);

    const encPath = path.join(this.dataDir, `${dbName}.sqlite`);
    const tmpOut = encPath + '.tmp';
    fs.writeFileSync(tmpOut, out);
    fs.renameSync(tmpOut, encPath);
    this._dirty.delete(dbName);
    return true;
  }

  _getDb(dbName) {
    if (this._dbs.has(dbName)) return this._dbs.get(dbName);

    let filePath;
    if (this._isEncrypted(dbName)) {
      filePath = this._decryptToTemp(dbName);
    } else {
      filePath = path.join(this.dataDir, `${dbName}.sqlite`);
    }

    const db = new SQLiteDB(filePath);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    this._dbs.set(dbName, db);
    return db;
  }

  _markDirty(dbName) {
    if (this._isEncrypted(dbName)) this._dirty.add(dbName);
  }

  closeDatabase(dbName) {
    if (this._isEncrypted(dbName)) this._encryptToDisk(dbName);
    const db = this._dbs.get(dbName);
    if (db) { db.close(); this._dbs.delete(dbName); }
    const tp = this._tempPaths.get(dbName);
    if (tp && fs.existsSync(tp)) { try { fs.unlinkSync(tp); } catch {} this._tempPaths.delete(dbName); }
  }

  setEncryptionKey(dbName, key) { this._keys.set(dbName, key); }

  ensureDatabase(dbName) {
    const filePath = path.join(this.dataDir, `${dbName}.sqlite`);
    if (!fs.existsSync(filePath)) {
      this._getDb(dbName);
      if (this._isEncrypted(dbName)) { this._markDirty(dbName); this._encryptToDisk(dbName); }
    }
  }

  createDatabase(dbName, encryptionKey) {
    const filePath = path.join(this.dataDir, `${dbName}.sqlite`);
    if (fs.existsSync(filePath)) throw new Error(`Database '${dbName}' already exists`);
    if (encryptionKey) this._keys.set(dbName, encryptionKey);
    this._getDb(dbName);
    if (encryptionKey) { this._markDirty(dbName); this._encryptToDisk(dbName); }
    console.log(`[sqlite] Created: ${dbName}${encryptionKey ? ' (encrypted)' : ''}`);
  }

  listDatabases() {
    if (!fs.existsSync(this.dataDir)) return [];
    return fs.readdirSync(this.dataDir)
      .filter(f => f.endsWith('.sqlite') && !f.endsWith('.tmp'))
      .map(f => f.replace('.sqlite', ''))
      .sort();
  }

  isEncryptedOnDisk(dbName) {
    try {
      const p = path.join(this.dataDir, `${dbName}.sqlite`);
      if (!fs.existsSync(p)) return false;
      const h = fs.readFileSync(p, { length: 16 }).toString('utf-8', 0, 15);
      return !h.startsWith('SQLite format');
    } catch { return false; }
  }

  listTables(dbName) {
    const db = this._getDb(dbName);
    return db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_aurora%' ORDER BY name"
    ).all().map(r => r.name);
  }

  query(dbName, sql) {
    const db = this._getDb(dbName);
    const stmt = db.prepare(sql);
    const columns = stmt.columns().map(c => ({ name: c.name, type: mapSQLiteType(c.type) }));
    const rows = stmt.all().map(row => columns.map(col => row[col.name]));
    return { columns, rows };
  }

  execute(dbName, sql) {
    const db = this._getDb(dbName);
    const result = db.prepare(sql).run();
    this._markDirty(dbName);
    if (this._isEncrypted(dbName)) {
      setImmediate(() => this._encryptToDisk(dbName));
    }
    return { changes: result.changes || 0, lastInsertRowid: result.lastInsertRowid || 0 };
  }

  shutdown() {
    for (const dbName of [...this._dirty]) { try { this._encryptToDisk(dbName); } catch {} }
    for (const dbName of [...this._dbs.keys()]) { this.closeDatabase(dbName); }
  }
}

function mapSQLiteType(t) {
  if (!t) return 'VARCHAR';
  t = t.toUpperCase();
  if (t.includes('INT')) return 'INTEGER';
  if (t.includes('REAL') || t.includes('FLOAT') || t.includes('DOUBLE')) return 'FLOAT';
  if (t.includes('BLOB')) return 'BLOB';
  if (t.includes('BOOL')) return 'TINYINT';
  return 'VARCHAR';
}

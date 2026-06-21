/**
 * sqlite-engine.mjs — SQLite Database Engine
 *
 * Manages SQLite databases in a directory. Each database is a separate
 * .sqlite file. Supports query (SELECT → rows with column metadata) and
 * execute (INSERT/UPDATE/DELETE/DDL → changes count).
 */

import { Database as SQLiteDB } from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

export class Database {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this._dbs = new Map(); // dbName → SQLiteDB instance
  }

  _getDb(dbName) {
    if (this._dbs.has(dbName)) return this._dbs.get(dbName);

    const filePath = path.join(this.dataDir, `${dbName}.sqlite`);
    const db = new SQLiteDB(filePath);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    this._dbs.set(dbName, db);
    return db;
  }

  ensureDatabase(dbName) {
    const filePath = path.join(this.dataDir, `${dbName}.sqlite`);
    if (!fs.existsSync(filePath)) {
      this._getDb(dbName); // Creates the file
      console.log(`[sqlite] Created database: ${dbName} (${filePath})`);
    }
  }

  createDatabase(dbName) {
    const filePath = path.join(this.dataDir, `${dbName}.sqlite`);
    if (fs.existsSync(filePath)) {
      throw new Error(`Database '${dbName}' already exists`);
    }
    this._getDb(dbName);
    console.log(`[sqlite] Created database: ${dbName}`);
  }

  listDatabases() {
    const files = fs.readdirSync(this.dataDir).filter(f => f.endsWith('.sqlite'));
    return files.map(f => f.replace('.sqlite', '')).sort();
  }

  listTables(dbName) {
    const db = this._getDb(dbName);
    const rows = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_aurora%' ORDER BY name"
    ).all();
    return rows.map(r => r.name);
  }

  /**
   * Execute a SELECT-type query, returning rows with column metadata.
   */
  query(dbName, sql) {
    const db = this._getDb(dbName);
    const stmt = db.prepare(sql);

    // Extract column names
    const columns = stmt.columns().map(c => ({
      name: c.name,
      type: mapSQLiteType(c.type),
    }));

    const rows = stmt.all().map(row =>
      columns.map(col => row[col.name])
    );

    return { columns, rows };
  }

  /**
   * Execute a non-SELECT statement (INSERT, UPDATE, DELETE, DDL).
   */
  execute(dbName, sql) {
    const db = this._getDb(dbName);
    const result = db.prepare(sql).run();
    return {
      changes: result.changes || 0,
      lastInsertRowid: result.lastInsertRowid || 0,
    };
  }
}

function mapSQLiteType(sqliteType) {
  if (!sqliteType) return 'VARCHAR';
  const t = sqliteType.toUpperCase();
  if (t.includes('INT')) return 'INTEGER';
  if (t.includes('REAL') || t.includes('FLOAT') || t.includes('DOUBLE')) return 'FLOAT';
  if (t.includes('BLOB')) return 'BLOB';
  if (t.includes('BOOL')) return 'TINYINT';
  return 'VARCHAR';
}

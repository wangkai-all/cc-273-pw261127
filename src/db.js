// src/db.js
// SQLite storage: metadata tables, the fictional events table, backups and
// shadow tables. Uses node:sqlite (built into Node 22+), no external deps.

import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { SCHEMA_VERSION, nowIso } from "./config.js";
import { CLEAR_COLUMNS, ENCRYPTED_COLUMNS } from "./schema.js";

export function openDb(dbPath, { create = true } = {}) {
  if (create) fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA busy_timeout = 5000;");
  db.exec("PRAGMA synchronous = FULL;");
  return db;
}

const META_SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS keyring (
  key_id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  label TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  activated_at TEXT,
  retiring_at TEXT,
  destroy_eligible_at TEXT,
  destroyed_at TEXT,
  replaces TEXT,
  note TEXT
);

CREATE TABLE IF NOT EXISTS purposes (
  purpose TEXT PRIMARY KEY,
  revoked_at TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  strategy TEXT NOT NULL,
  chunk_size INTEGER NOT NULL,
  from_key_id TEXT NOT NULL,
  to_key_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  column_name TEXT NOT NULL,
  total_rows INTEGER,
  processed_rows INTEGER NOT NULL DEFAULT 0,
  migrated_rows INTEGER NOT NULL DEFAULT 0,
  skipped_rows INTEGER NOT NULL DEFAULT 0,
  last_row_id INTEGER NOT NULL DEFAULT 0,
  backup_table TEXT,
  backup_total_rows INTEGER,
  backup_dropped_at TEXT,
  grace_seconds INTEGER NOT NULL DEFAULT 0,
  cutover_at TEXT,
  rollback_last_row_id INTEGER NOT NULL DEFAULT 0,
  rollback_processed_rows INTEGER NOT NULL DEFAULT 0,
  rollback_restored INTEGER NOT NULL DEFAULT 0,
  rollback_conflicts INTEGER NOT NULL DEFAULT 0,
  verified_rows INTEGER NOT NULL DEFAULT 0,
  verify_last_row_id INTEGER NOT NULL DEFAULT 0,
  verification_errors INTEGER NOT NULL DEFAULT 0,
  heartbeat_at TEXT,
  owner TEXT,
  owner_pid INTEGER,
  owner_host TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS run_touched (
  run_id TEXT NOT NULL,
  row_id INTEGER NOT NULL,
  wrote_hash TEXT NOT NULL,
  at TEXT NOT NULL,
  PRIMARY KEY (run_id, row_id)
);

CREATE TABLE IF NOT EXISTS run_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  at TEXT NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL,
  detail TEXT
);

-- Plaintext is deliberately NOT stored here. The cache is process memory only,
-- so a crash cannot leave decrypted values in a temp file or on disk.
CREATE TABLE IF NOT EXISTS leases (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  run_id TEXT,
  holder TEXT NOT NULL,
  key_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  column_name TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  released_at TEXT
);

CREATE INDEX IF NOT EXISTS runs_status_idx ON runs(status);
CREATE INDEX IF NOT EXISTS leases_active_idx ON leases(released_at, expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS one_live_run
  ON runs((1))
  WHERE status IN ('running','paused','interrupted','verifying','rolling_back','rollback_interrupted','failed');
`;

const EVENTS_SCHEMA = `
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at TEXT NOT NULL,
  region TEXT NOT NULL,
  plan TEXT NOT NULL,
  revenue_minor INTEGER NOT NULL,
  customer_email BLOB,
  session_label BLOB,
  audit_ref BLOB
);
`;

export function ensureSchema(db) {
  db.exec(META_SCHEMA);
  db.exec(EVENTS_SCHEMA);
  const row = db.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get();
  if (!row) {
    db.prepare("INSERT INTO meta(key, value) VALUES (?, ?)").run(
      "schema_version",
      String(SCHEMA_VERSION),
    );
    db.prepare("INSERT INTO meta(key, value) VALUES (?, ?)").run("created_at", nowIso());
  }
  db.prepare(
    "INSERT OR IGNORE INTO purposes(purpose, revoked_at, updated_at) VALUES (?, NULL, ?)",
  ).run("analytics", nowIso());
  db.prepare(
    "INSERT OR IGNORE INTO purposes(purpose, revoked_at, updated_at) VALUES (?, NULL, ?)",
  ).run("pii", nowIso());
  db.prepare(
    "INSERT OR IGNORE INTO purposes(purpose, revoked_at, updated_at) VALUES (?, NULL, ?)",
  ).run("audit", nowIso());
}

export function getMeta(db, key) {
  const row = db.prepare("SELECT value FROM meta WHERE key = ?").get(key);
  return row ? row.value : null;
}

export function setMeta(db, key, value) {
  db.prepare(
    "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
  ).run(key, value);
}

export function transaction(db, fn) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      /* already rolled back */
    }
    throw err;
  }
}

export function newTableSuffix() {
  return randomBytes(6).toString("hex");
}

export function backupTableName() {
  return `events_backup_${newTableSuffix()}`;
}

export function shadowTableName() {
  return `events_shadow_${newTableSuffix()}`;
}

export function createBackupTable(db, backupName, column) {
  // Empty pre-image table holding only the row id and the one column this run
  // migrates. Rollback restores exactly that column, so clear columns and other
  // purposes' ciphertext are never copied: a pii run's backup must not pin the
  // analytics key, and the backup stays roughly one column wide instead of a
  // full table copy.
  if (!/^events_backup_[0-9a-f]{12}$/.test(backupName)) {
    throw new Error(`invalid backup table name: ${backupName}`);
  }
  if (!ENCRYPTED_COLUMNS.includes(column)) {
    throw new Error(`invalid backup column: ${column}`);
  }
  db.exec(`CREATE TABLE IF NOT EXISTS ${backupName} (
    id INTEGER PRIMARY KEY,
    ${column} BLOB NOT NULL
  )`);
  return 0;
}

export function createShadowTable(db, shadowName) {
  // Copy clear columns verbatim; encrypted columns are re-encrypted as rows are
  // read. The shadow keeps the same row ids so AAD row binding stays stable.
  const clear = CLEAR_COLUMNS.join(", ");
  db.exec(`
    CREATE TABLE IF NOT EXISTS ${shadowName} (
      id INTEGER PRIMARY KEY,
      ${clear},
      ${ENCRYPTED_COLUMNS.join(" BLOB, ")} BLOB
    )
  `);
  db.exec(`INSERT INTO ${shadowName}(id, ${clear}) SELECT id, ${clear} FROM events`);
  return db.prepare(`SELECT COUNT(*) AS n FROM ${shadowName}`).get().n;
}

export function dropTable(db, name, allowedRe) {
  if (!allowedRe.test(name)) throw new Error(`refusing to drop unvalidated table name: ${name}`);
  db.exec(`DROP TABLE IF EXISTS ${name}`);
}

export function tableExists(db, name, allowedRe) {
  if (!allowedRe.test(name)) throw new Error(`refusing to inspect unvalidated table name: ${name}`);
  return Boolean(
    db.prepare("SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = ?").get(name),
  );
}

export function countRows(db, table) {
  const allowed = table === "events" || /^events_(backup|shadow)_[0-9a-f]{12}$/.test(table);
  if (!allowed) throw new Error(`refusing to count unvalidated table: ${table}`);
  return db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
}

export function listBackupTables(db) {
  return db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'events_backup_%' ORDER BY name",
    )
    .all()
    .map((r) => r.name)
    .filter((n) => /^events_backup_[0-9a-f]{12}$/.test(n));
}

export function listShadowTables(db) {
  return db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'events_shadow_%' ORDER BY name",
    )
    .all()
    .map((r) => r.name)
    .filter((n) => /^events_shadow_[0-9a-f]{12}$/.test(n));
}

export function columnTypes(db, table) {
  return db.prepare(`PRAGMA table_info(${table})`).all();
}

export function encodeBlob(value) {
  if (value == null) return null;
  if (Buffer.isBuffer(value)) return new Uint8Array(value);
  return new Uint8Array(value);
}

export function decodeBlob(value) {
  if (value == null) return null;
  return Buffer.isBuffer(value) ? value : Buffer.from(value);
}

export function toInt(value) {
  return typeof value === "bigint" ? Number(value) : value;
}

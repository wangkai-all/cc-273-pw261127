// src/keyring.js
// Local test keyring. Keys are generated locally with CSPRNG, stored as raw
// bytes in files with mode 0600 under <data>/keyring, and never logged or
// returned to the browser. Metadata (status, purpose, fingerprint) lives in
// SQLite. This is explicitly NOT an integration with a real key service.

import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { KEY_BYTES, encodeKeyId, fingerprint, parseKeyId, tryEnvelopeKeyId, MIN_ENVELOPE_BYTES } from "./crypto.js";
import { nowIso } from "./config.js";
import { transaction } from "./db.js";
import { activeLeasesForKey, activeLeasesForPurpose } from "./leases.js";

const KEY_FILE_RE = /^[0-9a-f]{16}\.key$/;

/** True when `table` has `column`. Used to skip legacy full-row backups that
 * were created for a different purpose and therefore lack this column. */
function tableHasColumn(db, table, column) {
  return db
    .prepare(`SELECT 1 AS ok FROM pragma_table_info(?) WHERE name = ?`)
    .get(table, column) != null;
}

export class KeyringError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "KeyringError";
    this.code = code;
    Object.assign(this, details);
  }
}

export function ensureKeyringDir(keyringDir) {
  fs.mkdirSync(keyringDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(keyringDir, 0o700);
}

export function keyFilePath(keyringDir, keyId) {
  if (!/^[0-9a-f]{16}$/.test(keyId)) throw new KeyringError("BAD_KEY_ID", "invalid key id");
  return path.join(keyringDir, `${keyId}.key`);
}

function readKeyBytes(keyringDir, keyId) {
  const file = keyFilePath(keyringDir, keyId);
  let raw;
  try {
    raw = fs.readFileSync(file);
  } catch {
    throw new KeyringError("KEY_MATERIAL_MISSING", `key material for ${keyId} is not available`);
  }
  const key = Buffer.from(raw.toString("utf8").trim(), "base64");
  if (key.length !== KEY_BYTES) {
    key.fill(0);
    throw new KeyringError("KEY_MATERIAL_CORRUPT", `key material for ${keyId} has wrong length`);
  }
  return key;
}

function writeKeyBytes(keyringDir, keyId, key) {
  ensureKeyringDir(keyringDir);
  const file = keyFilePath(keyringDir, keyId);
  const tmp = `${file}.${process.pid}.tmp`;
  // Write via an exclusive 0600 fd; rename is atomic on the same filesystem.
  const fd = fs.openSync(tmp, "wx", 0o600);
  try {
    fs.writeSync(fd, `${key.toString("base64")}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
  fs.chmodSync(file, 0o600);
}

export function listKeys(db) {
  return db
    .prepare(
      `SELECT key_id, purpose, label, fingerprint, status, created_at, activated_at,
              retiring_at, destroy_eligible_at, destroyed_at, replaces, note
       FROM keyring ORDER BY key_id ASC`,
    )
    .all();
}

export function getKeyRecord(db, keyId) {
  return db.prepare("SELECT * FROM keyring WHERE key_id = ?").get(keyId) ?? null;
}

export function activeKeyForPurpose(db, purpose) {
  return (
    db
      .prepare("SELECT * FROM keyring WHERE purpose = ? AND status = 'active' LIMIT 1")
      .get(purpose) ?? null
  );
}

/**
 * Load a usable key by id for decryption. Refuses destroyed or staged keys.
 * Staged keys have not been used for writes yet by policy.
 */
export function loadKeyForRead(db, keyringDir, keyId, purpose) {
  const rec = getKeyRecord(db, keyId);
  if (!rec) throw new KeyringError("UNKNOWN_KEY", `unknown key ${keyId}`);
  if (rec.purpose !== purpose) {
    throw new KeyringError(
      "PURPOSE_MISMATCH",
      `key ${keyId} is bound to purpose "${rec.purpose}", not "${purpose}"`,
    );
  }
  if (rec.status === "destroyed") {
    throw new KeyringError("KEY_DESTROYED", `key ${keyId} has been destroyed`);
  }
  if (rec.status === "staged") {
    throw new KeyringError("KEY_NOT_ACTIVE", `key ${keyId} is staged and not yet usable`);
  }
  return readKeyBytes(keyringDir, keyId);
}

/** Load a key for writes: must be the active key for the purpose. */
export function loadKeyForWrite(db, keyringDir, purpose) {
  const rec = activeKeyForPurpose(db, purpose);
  if (!rec) throw new KeyringError("NO_ACTIVE_KEY", `no active key for purpose ${purpose}`);
  return { key: readKeyBytes(keyringDir, rec.key_id), record: rec };
}

export function loadKeyForMigration(db, keyringDir, keyId) {
  const rec = getKeyRecord(db, keyId);
  if (!rec) throw new KeyringError("UNKNOWN_KEY", `unknown key ${keyId}`);
  if (rec.status === "destroyed") {
    throw new KeyringError("KEY_DESTROYED", `key ${keyId} has been destroyed`);
  }
  return { key: readKeyBytes(keyringDir, keyId), record: rec };
}

function nextKeySeq(db) {
  const row = db.prepare("SELECT MAX(CAST(key_id AS TEXT)) AS m FROM keyring").get();
  // key_id is zero-padded hex, so lexicographic max equals numeric max.
  if (!row || !row.m) return 1;
  const max = parseKeyId(row.m);
  return Number.isFinite(max) ? max + 1 : 1;
}

/**
 * Create a key for a purpose. First key for a purpose may be created active
 * with activate=true; all later keys are staged until explicitly promoted.
 */
export function createKey(db, keyringDir, { purpose, label = "", activate = false, replaces = null }) {
  const keyId = encodeKeyId(nextKeySeq(db));
  const key = randomBytes(KEY_BYTES);
  const fp = fingerprint(key);
  writeKeyBytes(keyringDir, keyId, key);
  key.fill(0);
  const at = nowIso();
  const existingActive = activeKeyForPurpose(db, purpose);
  const status = activate && !existingActive ? "active" : "staged";
  transaction(db, () => {
    db.prepare(
      `INSERT INTO keyring(key_id, purpose, label, fingerprint, status, created_at, activated_at, replaces, note)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      keyId,
      purpose,
      label || `${purpose}-${keyId.slice(-4)}`,
      fp,
      status,
      at,
      status === "active" ? at : null,
      replaces,
      null,
    );
  });
  return getKeyRecord(db, keyId);
}

/**
 * Promote a staged key to active. The previous active key for the purpose moves
 * to "retiring" and gets an eligibility timestamp, but its material stays
 * available until destroy conditions are met.
 */
export function promoteKey(db, keyringDir, keyId, { graceSeconds = 0 } = {}) {
  const rec = getKeyRecord(db, keyId);
  if (!rec) throw new KeyringError("UNKNOWN_KEY", `unknown key ${keyId}`);
  if (rec.status === "destroyed") throw new KeyringError("KEY_DESTROYED", "cannot promote a destroyed key");
  if (rec.status === "active") return { key: rec, retired: null };
  if (rec.status === "retiring") {
    throw new KeyringError("KEY_RETIRING", "cannot re-activate a retiring key; create a new one");
  }
  if (rec.status !== "staged") throw new KeyringError("BAD_STATUS", `cannot promote from ${rec.status}`);
  const at = nowIso();
  const eligible = new Date(Date.now() + graceSeconds * 1000).toISOString();
  const retired = transaction(db, () => {
    const prev = activeKeyForPurpose(db, rec.purpose);
    db.prepare("UPDATE keyring SET status = 'active', activated_at = ? WHERE key_id = ?").run(at, keyId);
    if (prev) {
      db.prepare(
        `UPDATE keyring SET status = 'retiring', retiring_at = ?, destroy_eligible_at = ?
         WHERE key_id = ?`,
      ).run(at, eligible, prev.key_id);
    }
    return prev;
  });
  return { key: getKeyRecord(db, keyId), retired: retired ? getKeyRecord(db, retired.key_id) : null };
}

/**
 * Check whether a key can be destroyed. Returns structured reasons, all of
 * which must be resolved before material deletion:
 *  - no rows still encrypted under this key for its purpose column
 *  - no active query/migration lease naming the key or its purpose
 *  - grace period since retirement has elapsed
 *  - no live migration run uses it as source or target
 *  - purpose not merely "revoked" but explicitly past revocation retention
 */
export function destructionReadiness(db, keyId, { graceSeconds = 0, now = new Date() } = {}) {  const rec = getKeyRecord(db, keyId);
  if (!rec) throw new KeyringError("UNKNOWN_KEY", `unknown key ${keyId}`);
  const reasons = [];
  if (rec.status === "destroyed") {
    return { ready: false, reasons: ["already_destroyed"], record: rec };
  }
  if (rec.status === "staged") reasons.push("staged_key_never_destroy_until_promoted_or_abandoned");
  if (rec.status === "active") reasons.push("key_is_active");
  if (rec.status === "retiring") {
    const eligible = rec.destroy_eligible_at ? new Date(rec.destroy_eligible_at) : null;
    if (!eligible) reasons.push("no_retirement_timestamp");
    else if (eligible > now) reasons.push("grace_period_not_elapsed");
  }

  // Count references to this key across the live table, backups and shadows.
  const references = countSourceReferences(db, rec.purpose, keyId);
  if (references.live > 0) reasons.push(`live_rows_still_under_key:${references.live}`);
  if (references.backup > 0) reasons.push(`backup_rows_still_under_key:${references.backup}`);
  if (references.shadow > 0) reasons.push(`shadow_rows_still_under_key:${references.shadow}`);

  const leases = activeLeasesForKey(db, keyId, now);
  if (leases.length > 0) reasons.push(`active_leases:${leases.length}`);
  const purposeLeases = activeLeasesForPurpose(db, rec.purpose, now);
  if (purposeLeases.length > 0) reasons.push(`active_purpose_leases:${purposeLeases.length}`);

  const liveRuns = db
    .prepare(
      `SELECT COUNT(*) AS n FROM runs
       WHERE (from_key_id = ? OR to_key_id = ?)
         AND status IN ('running','paused','interrupted','verifying','rolling_back','rollback_interrupted','failed')`,
    )
    .get(keyId, keyId).n;
  if (liveRuns > 0) reasons.push(`live_runs:${liveRuns}`);

  return {
    ready: reasons.length === 0,
    reasons,
    record: rec,
    rowsRemaining: references.live,
    references,
  };
}

const KEY_ID_HEX = /^[0-9a-f]{16}$/;
const PURPOSE_COLUMN = { analytics: "session_label", pii: "customer_email", audit: "audit_ref" };

/**
 * Count references to a key id across the live table, rollback backups and
 * shadow tables. A backup or shadow still holding old-key ciphertext blocks
 * destruction: dropping the key would make rollback impossible. Envelope key id
 * sits at ASCII offset 6..22.
 *
 * Backup tables are scoped to the column their run migrated (and to that run's
 * purpose): a pii run's backup never stores session_label, so it cannot pin the
 * analytics key. Backups written by older versions stored full rows; they are
 * still only consulted for their own run's column.
 */
export function countSourceReferences(db, purpose, keyId) {
  if (!KEY_ID_HEX.test(keyId)) throw new Error("invalid key id");
  const column = PURPOSE_COLUMN[purpose];
  if (!column) throw new Error("unknown purpose");
  const backupTables = db
    .prepare(
      `SELECT DISTINCT backup_table AS name FROM runs
       WHERE backup_table IS NOT NULL AND column_name = ?`,
    )
    .all(column)
    .map((r) => r.name)
    .filter((n) => /^events_backup_[0-9a-f]{12}$/.test(n))
    .filter((n) => tableHasColumn(db, n, column));
  const tables = [
    { name: "events", kind: "live" },
    ...backupTables.map((name) => ({ name, kind: "backup" })),
    ...db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'events_shadow_%'",
      )
      .all()
      .map((r) => r.name)
      .filter((n) => /^events_shadow_[0-9a-f]{12}$/.test(n))
      .filter((n) => tableHasColumn(db, n, column))
      .map((name) => ({ name, kind: "shadow" })),
  ];
  const out = { live: 0, backup: 0, shadow: 0, total: 0, tables: [] };
  for (const table of tables) {
    const rows = db.prepare(`SELECT ${column} AS v FROM ${table.name} WHERE ${column} IS NOT NULL`).all();
    let n = 0;
    for (const row of rows) {
      const buf = Buffer.isBuffer(row.v) ? row.v : Buffer.from(row.v);
      if (tryEnvelopeKeyId(buf) === keyId) n += 1;
    }
    out[table.kind] += n;
    out.total += n;
    if (n > 0) out.tables.push({ table: table.name, kind: table.kind, rows: n });
  }
  return out;
}

export function countRowsUnderKeyEverywhere(db, purpose, keyId) {
  return countSourceReferences(db, purpose, keyId).total;
}

export function countRowsUnderKey(db, purpose, keyId) {
  if (!KEY_ID_HEX.test(keyId)) throw new Error("invalid key id");
  const column = PURPOSE_COLUMN[purpose];
  if (!column) throw new Error("unknown purpose");
  const rows = db.prepare(`SELECT ${column} AS v FROM events WHERE ${column} IS NOT NULL`).all();
  let n = 0;
  for (const row of rows) {
    const buf = Buffer.isBuffer(row.v) ? row.v : Buffer.from(row.v);
    if (tryEnvelopeKeyId(buf) === keyId) n += 1;
  }
  return n;
}

/**
 * Destroy key material after all conditions pass. Does not touch rows: by the
 * time this is allowed, no rows reference the key.
 */
/**
 * Destroy key material. There is deliberately no force/bypass: readiness is
 * evaluated inside the same IMMEDIATE transaction that flips the status, so a
 * query can never slip a lease in between the check and the destroy. The only
 * way to retire a key is to make every condition true.
 */
export function destroyKey(db, keyringDir, keyId, { graceSeconds = 0, now = new Date() } = {}) {
  const readiness = transaction(db, () => {
    const r = destructionReadiness(db, keyId, { graceSeconds, now });
    if (!r.ready) {
      throw new KeyringError("NOT_READY", "key is not eligible for destruction", {
        reasons: r.reasons,
      });
    }
    db.prepare("UPDATE keyring SET status = 'destroyed', destroyed_at = ? WHERE key_id = ?").run(
      now.toISOString(),
      keyId,
    );
    return r;
  });
  // Delete material only after the status flip is durable. If unlink fails the
  // key is already unusable (loadKeyForRead refuses destroyed), which is the
  // fail-safe direction: no reader can decrypt, and cleanup can be retried.
  const file = keyFilePath(keyringDir, keyId);
  let materialDeleted = true;
  try {
    fs.unlinkSync(file);
  } catch (err) {
    if (err.code !== "ENOENT") materialDeleted = false;
  }
  return {
    keyId,
    destroyedAt: now.toISOString(),
    materialDeleted,
  };
}

export function purposeState(db, purpose) {
  const row = db.prepare("SELECT * FROM purposes WHERE purpose = ?").get(purpose);
  return row ? { purpose: row.purpose, revokedAt: row.revoked_at, updatedAt: row.updated_at } : null;
}

export function allPurposeStates(db) {
  return db.prepare("SELECT * FROM purposes ORDER BY purpose ASC").all();
}

export function revokePurpose(db, purpose, { now = new Date() } = {}) {
  const state = purposeState(db, purpose);
  if (!state) throw new KeyringError("UNKNOWN_PURPOSE", `unknown purpose ${purpose}`);
  if (state.revokedAt) return { purpose, revokedAt: state.revokedAt, alreadyRevoked: true };
  const at = now.toISOString();
  db.prepare("UPDATE purposes SET revoked_at = ?, updated_at = ? WHERE purpose = ?").run(at, at, purpose);
  return { purpose, revokedAt: at, alreadyRevoked: false };
}

export function restorePurpose(db, purpose, { now = new Date() } = {}) {
  const state = purposeState(db, purpose);
  if (!state) throw new KeyringError("UNKNOWN_PURPOSE", `unknown purpose ${purpose}`);
  const at = now.toISOString();
  db.prepare("UPDATE purposes SET revoked_at = NULL, updated_at = ? WHERE purpose = ?").run(at, purpose);
  return { purpose, revokedAt: null };
}

export function keyringManifest(db, { includeFingerprints = true } = {}) {
  const keys = db
    .prepare(
      `SELECT key_id, purpose, label, fingerprint, status, created_at, activated_at,
              retiring_at, destroy_eligible_at, destroyed_at, replaces
       FROM keyring ORDER BY purpose, key_id`,
    )
    .all()
    .map((k) => ({
      keyId: k.key_id,
      purpose: k.purpose,
      label: k.label,
      ...(includeFingerprints ? { fingerprint: k.fingerprint } : {}),
      status: k.status,
      createdAt: k.created_at,
      activatedAt: k.activated_at,
      retiringAt: k.retiring_at,
      destroyEligibleAt: k.destroy_eligible_at,
      destroyedAt: k.destroyed_at,
      replaces: k.replaces,
    }));
  const purposes = allPurposeStates(db).map((p) => ({
    purpose: p.purpose,
    revokedAt: p.revoked_at,
    updatedAt: p.updated_at,
  }));
  const distribution = {};
  for (const col of ["customer_email", "session_label", "audit_ref"]) {
    const rows = db.prepare(`SELECT ${col} AS v FROM events WHERE ${col} IS NOT NULL`).all();
    const counts = {};
    for (const row of rows) {
      const buf = Buffer.isBuffer(row.v) ? row.v : Buffer.from(row.v);
      if (buf.length < MIN_ENVELOPE_BYTES) {
        counts.corrupt = (counts.corrupt || 0) + 1;
        continue;
      }
      const kid = tryEnvelopeKeyId(buf) ?? "corrupt";
      const purpose = { customer_email: "pii", session_label: "analytics", audit_ref: "audit" }[col];
      const key = `${purpose}:${kid}`;
      counts[key] = (counts[key] || 0) + 1;
    }
    distribution[col] = counts;
  }
  return {
    generatedAt: nowIso(),
    schemaVersion: 1,
    cipher: "AES-256-GCM",
    keys,
    purposes,
    distribution,
    warnings: manifestWarnings(db),
  };
}

function manifestWarnings(db) {
  const warnings = [];
  const liveRuns = db
    .prepare("SELECT id, status FROM runs WHERE status IN ('running','paused','interrupted')")
    .all();
  if (liveRuns.length) warnings.push(`${liveRuns.length} migration run(s) are live`);
  const revoked = allPurposeStates(db).filter((p) => p.revoked_at);
  for (const p of revoked) warnings.push(`purpose "${p.purpose}" is revoked; its ciphertext remains at rest`);
  const staged = db.prepare("SELECT COUNT(*) AS n FROM keyring WHERE status = 'staged'").get().n;
  if (staged) warnings.push(`${staged} staged key(s) not yet active`);
  return warnings;
}

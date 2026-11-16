// src/rotation.js
// In-place chunked re-encryption with resumability.
//
// Strategy: in-place, row-range chunks ordered by id.
//  - Each chunk runs in a single IMMEDIATE transaction; a crash leaves the chunk
//    all-or-nothing, and the persisted cursor points at the last committed chunk.
//  - A backup table is written in the same transaction as each migrated chunk,
//    so rollback has a consistent pre-image regardless of where the process died.
//  - Writes that arrive during rotation always use the currently active key. A
//    chunk skips rows already carrying the target key id, so readers/writers
//    racing with the walk cannot be corrupted.
//  - A durable heartbeat marks the run "interrupted" only when the owning
//    process is gone; a stale heartbeat is never treated as completion.

import { randomBytes } from "node:crypto";
import { nowIso } from "./config.js";
import {
  BACKUP_TABLE_RE,
  COLUMN_TO_PURPOSE,
  LIVE_RUN_STATUSES,
} from "./schema.js";
import {
  backupTableName,
  countRows,
  createBackupTable,
  createShadowTable,
  dropTable,
  encodeBlob,
  decodeBlob,
  listBackupTables,
  listShadowTables,
  tableExists,
  transaction,
  newTableSuffix,
} from "./db.js";
import { acquireLease, releaseLease, LeaseError } from "./leases.js";
import { decryptValue, encodeKeyId, envelopeKeyId, encryptValue, tryEnvelopeKeyId } from "./crypto.js";
import { createHash } from "node:crypto";
import { PROCESS_TAG, HOST } from "./identity.js";
import {
  KeyringError,
  activeKeyForPurpose,
  getKeyRecord,
  loadKeyForMigration,
  countRowsUnderKeyEverywhere,
} from "./keyring.js";

export class RotationError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "RotationError";
    this.code = code;
    Object.assign(this, details);
  }
}

const STRATEGY = "in_place_chunked";
/** A run whose owner has not checked in for this long is presumed dead. */
const OWNER_STALE_MS = 60_000;

export function findLiveRun(db) {
  return (
    db
      .prepare(
        `SELECT * FROM runs
         WHERE status IN ('running','paused','interrupted','verifying','rolling_back','rollback_interrupted','failed')
         ORDER BY started_at DESC LIMIT 1`,
      )
      .get() ?? null
  );
}

export function getRun(db, runId) {
  return db.prepare("SELECT * FROM runs WHERE id = ?").get(runId) ?? null;
}

export function logRun(db, runId, level, message, detail = null) {
  db.prepare(
    "INSERT INTO run_log(run_id, at, level, message, detail) VALUES (?, ?, ?, ?, ?)",
  ).run(runId, nowIso(), level, message, detail == null ? null : JSON.stringify(detail));
}

export function runLog(db, runId, limit = 200) {
  return db
    .prepare("SELECT * FROM run_log WHERE run_id = ? ORDER BY seq DESC LIMIT ?")
    .all(runId, limit)
    .reverse();
}

function ownerTag() {
  return PROCESS_TAG;
}

/**
 * Decide whether the process that owns a run is still alive.
 *
 * A run owner is "host:pid:nonce". On the same host we check PID liveness
 * directly, because another local process (e.g. a CLI `status` call) must not
 * mistake a healthy server's run for a crashed one. Cross-host we can only use
 * the heartbeat. In both cases a stale heartbeat means the owner is wedged or
 * the PID was recycled, so the run is treated as interrupted. A live owner
 * refreshes the heartbeat at least once per chunk.
 */
export function ownerIsAlive(run, { now = new Date() } = {}) {
  if (!run.owner) return false;
  const heartbeat = run.heartbeat_at ? Date.parse(run.heartbeat_at) : NaN;
  if (!Number.isFinite(heartbeat) || now.getTime() - heartbeat > OWNER_STALE_MS) return false;
  const [host, pidText] = String(run.owner).split(":");
  const pid = Number.parseInt(pidText, 10);
  if (host === HOST && Number.isInteger(pid) && pid > 0) {
    if (pid === process.pid) return true;
    try {
      process.kill(pid, 0);
      return true;
    } catch (err) {
      if (err.code === "ESRCH") return false;
      // EPERM means the PID exists but belongs to someone else: still alive.
      return err.code === "EPERM";
    }
  }
  return true; // different host, recent heartbeat: assume alive
}

/**
 * Startup/status reconciliation. A run left "running" or "rolling_back" whose
 * owner process is gone becomes resumable ("interrupted"), never silently
 * completed. A live run owned by another process on this host is left alone.
 */
export function reconcileRuns(db, { now = new Date() } = {}) {
  const changed = [];
  const rows = db
    .prepare("SELECT * FROM runs WHERE status IN ('running','rolling_back')")
    .all();
  for (const run of rows) {
    if (ownerIsAlive(run, { now })) continue;
    const next = run.status === "running" ? "interrupted" : "rollback_interrupted";
    db.prepare("UPDATE runs SET status = ? WHERE id = ? AND status = ?").run(next, run.id, run.status);
    logRun(db, run.id, "warn", `run marked ${next}: owner process is no longer alive`, {
      previousOwner: run.owner,
      lastHeartbeat: run.heartbeat_at,
      lastRowId: run.last_row_id,
    });
    changed.push({ id: run.id, from: run.status, to: next, previousOwner: run.owner });
  }
  return changed;
}

/**
 * Create and start a migration run.
 *
 * Cutover ordering: the caller activates the new key BEFORE this backfill walk.
 * That way every concurrent write lands under the target key, and the forward
 * walk only has to convert pre-existing old-key rows. A row that a writer
 * re-encrypts under the target key while the walk is behind it is simply
 * skipped when reached, so there can be no old-key stragglers behind the cursor.
 */
export function startRun(
  db,
  keyringDir,
  { purpose, fromKeyId, toKeyId, chunkSize = 50, strategy = STRATEGY, ownerPid = process.pid },
) {
  if (strategy !== STRATEGY) {
    throw new RotationError(
      "STRATEGY_UNSUPPORTED",
      "only the in-place chunked strategy is implemented; shadow-copy switching is documented but not shipped",
    );
  }
  const column = { pii: "customer_email", analytics: "session_label", audit: "audit_ref" }[purpose];
  if (!column) throw new RotationError("BAD_PURPOSE", `unknown purpose ${purpose}`);

  const existing = findLiveRun(db);
  if (existing) {
    throw new RotationError(
      "RUN_IN_PROGRESS",
      `a run is already live: ${existing.id} (${existing.status})`,
      { runId: existing.id, status: existing.status },
    );
  }

  const from = getKeyRecord(db, fromKeyId);
  const to = getKeyRecord(db, toKeyId);
  if (!from || !to) throw new RotationError("UNKNOWN_KEY", "source or target key is missing");
  if (from.purpose !== purpose || to.purpose !== purpose) {
    throw new RotationError("PURPOSE_MISMATCH", "source/target key purpose does not match run purpose");
  }
  if (from.status === "destroyed" || from.status === "staged") {
    throw new RotationError("SOURCE_KEY_UNUSABLE", `source key is ${from.status}`);
  }
  if (from.status !== "retiring" && from.status !== "active") {
    throw new RotationError("SOURCE_KEY_UNUSABLE", `source key is ${from.status}`);
  }
  if (to.status !== "active") {
    throw new RotationError("TARGET_NOT_ACTIVE", `target key is ${to.status}; activate it first`);
  }
  if (fromKeyId === toKeyId) throw new RotationError("SAME_KEY", "source and target keys are identical");
  const active = activeKeyForPurpose(db, purpose);
  if (!active || active.key_id !== toKeyId) {
    throw new RotationError("TARGET_NOT_ACTIVE", "target is not the active key for this purpose");
  }

  const revocation = db.prepare("SELECT revoked_at FROM purposes WHERE purpose = ?").get(purpose);
  if (revocation?.revoked_at) {
    throw new RotationError(
      "PURPOSE_REVOKED",
      `purpose ${purpose} is revoked; restore or re-enable it before rotating`,
    );
  }

  // Pre-flight: a run handles exactly one source generation. If the column also
  // holds an older generation, refuse up front with the offending key ids instead
  // of failing mid-walk after some rows are already re-encrypted.
  const stray = strayGenerations(db, column, new Set([fromKeyId, toKeyId]));
  if (stray.length > 0) {
    throw new RotationError(
      "MULTI_GENERATION_REMAINING",
      `column ${column} still has rows under key(s) ${stray.join(", ")}; finish the older rotation first`,
      { keyIds: stray },
    );
  }

  const id = `run_${Date.now().toString(36)}_${randomBytes(3).toString("hex")}`;
  const total = countRows(db, "events");
  const at = nowIso();
  const backup = backupTableName();
  transaction(db, () => {
    db.prepare(
      `INSERT INTO runs(id, status, strategy, chunk_size, from_key_id, to_key_id, purpose, column_name,
                        total_rows, processed_rows, last_row_id, backup_table, started_at, heartbeat_at,
                        owner, owner_pid, owner_host)
       VALUES (?, 'running', ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      STRATEGY,
      chunkSize,
      fromKeyId,
      toKeyId,
      purpose,
      column,
      total,
      backup,
      at,
      at,
      ownerTag(),
      ownerPid,
      HOST,
    );
    createBackupTable(db, backup, column);
    logRun(db, id, "info", "run started after cutover to target key", {
      fromKeyId,
      toKeyId,
      purpose,
      column,
      totalRows: total,
      chunkSize,
      strategy: STRATEGY,
    });
  });
  return getRun(db, id);
}

export function touchHeartbeat(db, runId, { ownerPid = process.pid } = {}) {
  db.prepare("UPDATE runs SET heartbeat_at = ?, owner = ?, owner_pid = ? WHERE id = ?").run(
    nowIso(),
    ownerTag(),
    ownerPid,
    runId,
  );
}

/**
 * Migrate one chunk. Returns {done, processed, lastRowId}. All row reads and
 * writes for the chunk happen inside one transaction.
 *
 * Ownership rules inside the transaction:
 *  - envelope key id == target  -> skip (concurrent writer already used new key)
 *  - envelope key id == source  -> decrypt with source key, re-encrypt with target
 *  - envelope key id == other   -> hard error: refuse to guess, leave row intact
 */
export function migrateChunk(db, keyringDir, runId, { chunkSize, ownerPid = process.pid } = {}) {
  const run = getRun(db, runId);
  if (!run) throw new RotationError("UNKNOWN_RUN", `unknown run ${runId}`);
  if (!LIVE_RUN_STATUSES.includes(run.status)) {
    throw new RotationError("RUN_NOT_LIVE", `run ${runId} is ${run.status}`);
  }
  if (run.status !== "running") {
    throw new RotationError("RUN_NOT_RUNNING", `run ${runId} is ${run.status}; resume it first`);
  }
  const size = Math.min(Math.max(Number(chunkSize ?? run.chunk_size), 1), 500);
  const purpose = run.purpose;
  const column = run.column_name;
  if (COLUMN_TO_PURPOSE[column] !== purpose) {
    throw new RotationError("RUN_CORRUPT", "run purpose/column mismatch");
  }

  let src, dst;
  try {
    src = loadKeyForMigration(db, keyringDir, run.from_key_id);
    dst = loadKeyForMigration(db, keyringDir, run.to_key_id);
  } catch (err) {
    if (err instanceof KeyringError) {
      db.prepare("UPDATE runs SET status = 'paused', error = ? WHERE id = ?").run(err.message, runId);
      logRun(db, runId, "error", "cannot load migration keys; run paused", { code: err.code });
      throw new RotationError("KEYS_UNAVAILABLE", err.message, { cause: err.code });
    }
    throw err;
  }
  if (dst.record.status === "destroyed" || dst.record.status === "retiring") {
    throw new RotationError("TARGET_KEY_UNAVAILABLE", "target key is not usable for writes");
  }

  // Hold a lease on the source key for the duration of the chunk. The lease is
  // released in every path, including failure; the run row (not the lease) is
  // what pins the source key across a crash.
  let lease;
  try {
    lease = acquireLease(db, {
      kind: "migration",
      holder: ownerTag(),
      keyId: run.from_key_id,
      purpose,
      column,
      runId,
      ttlMs: 60_000,
    });
  } catch (err) {
    if (err instanceof LeaseError) {
      throw new RotationError("LEASE_REFUSED", err.message, { cause: err.code });
    }
    throw err;
  }

  let result;
  try {
    result = transaction(db, () => {
    const fresh = getRun(db, runId);
    if (!fresh || fresh.status !== "running") {
      throw new RotationError("RUN_NOT_RUNNING", "run state changed during chunk");
    }
    const rows = db
      .prepare(
        `SELECT id, ${column} AS v FROM events WHERE id > ? ORDER BY id ASC LIMIT ?`,
      )
      .all(fresh.last_row_id, size);
    if (rows.length === 0) {
      db.prepare(
        "UPDATE runs SET status = 'verifying', processed_rows = processed_rows, heartbeat_at = ?, owner = ?, owner_pid = ? WHERE id = ?",
      ).run(nowIso(), ownerTag(), ownerPid, runId);
      logRun(db, runId, "info", "walk reached end of table; moving to verification", {
        processed: fresh.processed_rows,
      });
      return { done: true, processed: 0, lastRowId: fresh.last_row_id, migrated: 0, skipped: 0 };
    }

    let migrated = 0;
    let skipped = 0;
    let lastId = fresh.last_row_id;

    for (const row of rows) {
      lastId = row.id;
      const env = decodeBlob(row.v);
      if (env == null) {
        skipped += 1;
        continue;
      }
      const kid = envelopeKeyId(env);
      if (kid === run.to_key_id) {
        skipped += 1;
        continue;
      }
      if (kid !== run.from_key_id) {
        throw new RotationError(
          "UNEXPECTED_KEY_ID",
          `row ${row.id} column ${column} carries key ${kid}, expected ${run.from_key_id} or ${run.to_key_id}`,
          { rowId: row.id, keyId: kid },
        );
      }
      let plaintext;
      try {
        plaintext = decryptValue(env, {
          key: src.key,
          purpose,
          rowId: row.id,
          column,
        });
      } catch (err) {
        throw new RotationError(
          "DECRYPT_FAILED",
          `row ${row.id} failed to decrypt; chunk rolled back, run left resumable`,
          { rowId: row.id, cause: err.code },
        );
      }
      const next = ensureEncrypted(plaintext, {
        key: dst.key,
        keyId: run.to_key_id,
        purpose,
        rowId: row.id,
        column,
      });
      // Backup pre-image exactly as it was before this chunk. Only the migrated
      // column is stored, so a run can never pin another purpose's key and the
      // backup cannot be mistaken for a usable copy of the row. Full-row replace
      // keyed by id makes re-visiting the same row idempotent.
      db.prepare(
        `INSERT OR REPLACE INTO ${run.backup_table}(id, ${column})
         SELECT id, ${column} FROM events WHERE id = ?`,
      ).run(row.id);
      db.prepare(`UPDATE events SET ${column} = ? WHERE id = ?`).run(encodeBlob(next), row.id);
      // Record the exact ciphertext this run wrote. Rollback uses this to prove
      // a live row is still *our* write before replacing it; if a concurrent
      // writer changed the row afterwards, rollback reports a conflict instead
      // of clobbering newer data.
      db.prepare(
        "INSERT OR REPLACE INTO run_touched(run_id, row_id, wrote_hash, at) VALUES (?, ?, ?, ?)",
      ).run(runId, row.id, ciphertextHash(next), nowIso());
      migrated += 1;
      plaintext = null; // drop the plaintext reference before leaving the loop
    }

    db.prepare(
      `UPDATE runs SET processed_rows = processed_rows + ?, migrated_rows = migrated_rows + ?,
                      skipped_rows = skipped_rows + ?, last_row_id = ?, heartbeat_at = ?,
                      owner = ?, owner_pid = ? WHERE id = ?`,
    ).run(migrated, migrated, skipped, lastId, nowIso(), ownerTag(), ownerPid, runId);

    return { done: false, processed: rows.length, migrated, skipped, lastRowId: lastId };
    });
  } catch (err) {
    // The chunk transaction rolled back as a unit. Record the failure and move
    // the run to a resumable-but-stopped state so an operator must decide:
    // resume from the cursor, or roll back from the backup. Never keep retrying
    // silently, and never leave the run claiming to be "running".
    try {
      db.prepare("UPDATE runs SET status = 'failed', error = ?, finished_at = ? WHERE id = ? AND status = 'running'").run(
        `${err.code || err.name}: ${err.message}`.slice(0, 500),
        nowIso(),
        runId,
      );
      logRun(db, runId, "error", "chunk failed; run stopped for operator decision", {
        code: err.code || err.name,
        rowId: err.rowId ?? null,
      });
    } catch {
      /* logging must not mask the original error */
    }
    throw err;
  } finally {
    releaseLease(db, lease.id);
  }
  return result;
}

function ciphertextHash(buf) {
  return createHash("sha256").update(buf).digest("hex").slice(0, 32);
}

/**
 * Distinct key ids present in one live column, excluding the allowed set.
 * Returns [] (not an error) for unreadable envelopes; the walk will surface
 * those as MALFORMED/UNEXPECTED rows with row ids.
 */
function strayGenerations(db, column, allowed) {
  const rows = db.prepare(`SELECT ${column} AS v FROM events WHERE ${column} IS NOT NULL`).all();
  const seen = new Set();
  for (const row of rows) {
    const buf = Buffer.isBuffer(row.v) ? row.v : Buffer.from(row.v);
    const kid = tryEnvelopeKeyId(buf);
    if (kid && !allowed.has(kid)) seen.add(kid);
  }
  return [...seen].sort();
}

function recordConflict(db, runId, rowId, reason) {
  db.prepare(
    "INSERT OR REPLACE INTO run_touched(run_id, row_id, wrote_hash, at) VALUES (?, ?, ?, ?)",
  ).run(runId, rowId, `conflict:${reason}`, nowIso());
}

function ensureEncrypted(plaintext, args) {
  return encryptValue(plaintext, args);
}

/**
 * Verify every row's ciphertext under the target key. Runs in bounded chunks
 * with a cursor; safe to resume. Rows under other key ids are reported as
 * errors rather than "verified".
 */
export function verifyChunk(db, keyringDir, runId, { chunkSize = 100 } = {}) {
  const run = getRun(db, runId);
  if (!run) throw new RotationError("UNKNOWN_RUN", `unknown run ${runId}`);
  if (run.status !== "verifying") {
    throw new RotationError("RUN_NOT_VERIFYING", `run ${runId} is ${run.status}`);
  }
  let key;
  try {
    key = loadKeyForMigration(db, keyringDir, run.to_key_id).key;
  } catch (err) {
    throw new RotationError("KEYS_UNAVAILABLE", err.message, { cause: err.code });
  }
  const cursor = Number(run.verify_last_row_id || 0);
  const rows = db
    .prepare(`SELECT id, ${run.column_name} AS v FROM events WHERE id > ? ORDER BY id ASC LIMIT ?`)
    .all(cursor, chunkSize);
  let ok = 0;
  let bad = 0;
  const errors = [];
  for (const row of rows) {
    const env = decodeBlob(row.v);
    if (env == null) {
      bad += 1;
      errors.push({ rowId: row.id, reason: "missing_ciphertext" });
      continue;
    }
    const kid = envelopeKeyId(env);
    if (kid !== run.to_key_id) {
      // Old-key rows behind the cursor mean the walk missed data; report it
      // rather than silently completing a half-rotated column.
      bad += 1;
      errors.push({ rowId: row.id, reason: "wrong_key", keyId: kid });
      continue;
    }
    try {
      decryptValue(env, { key, purpose: run.purpose, rowId: row.id, column: run.column_name });
      ok += 1;
    } catch (err) {
      bad += 1;
      errors.push({ rowId: row.id, reason: err.code || "decrypt_failed" });
    }
  }
  const newCursor = rows.length ? rows[rows.length - 1].id : cursor;
  const lastId = Number(
    db.prepare("SELECT COALESCE(MAX(id),0) AS n FROM events").get().n,
  );
  db.prepare(
    `UPDATE runs SET verify_last_row_id = ?, verified_rows = verified_rows + ?,
                    verification_errors = verification_errors + ?, heartbeat_at = ? WHERE id = ?`,
  ).run(newCursor, rows.length, bad, nowIso(), runId);
  if (errors.length) {
    logRun(db, runId, "error", "verification errors", { errors: errors.slice(0, 20), count: bad });
  }
  if (rows.length === 0 || newCursor >= lastId) {
    const finalBad = db.prepare("SELECT COALESCE(verification_errors,0) AS n FROM runs WHERE id = ?").get(runId).n;
    const verifiedRows = db.prepare("SELECT COALESCE(verified_rows,0) AS n FROM runs WHERE id = ?").get(runId).n;
    if (finalBad === 0) {
      db.prepare("UPDATE runs SET status = 'completed', finished_at = ? WHERE id = ?").run(nowIso(), runId);
      logRun(db, runId, "info", "verification passed; run completed", { rows: verifiedRows });
      return { done: true, ok, bad, verifiedRows, completed: true };
    }
    db.prepare("UPDATE runs SET status = 'failed', finished_at = ?, error = ? WHERE id = ?").run(
      nowIso(),
      `${finalBad} verification error(s)`,
      runId,
    );
    logRun(db, runId, "error", "verification failed; backup retained for rollback", { errors: finalBad });
    return { done: true, ok, bad, verifiedRows, completed: false };
  }
  return { done: false, ok, bad, verifiedRows: null, completed: false };
}

export function pauseRun(db, runId) {
  const run = getRun(db, runId);
  if (!run) throw new RotationError("UNKNOWN_RUN", `unknown run ${runId}`);
  if (run.status !== "running") throw new RotationError("RUN_NOT_RUNNING", `run is ${run.status}`);
  db.prepare("UPDATE runs SET status = 'paused' WHERE id = ?").run(runId);
  logRun(db, runId, "info", "run paused manually");
  return getRun(db, runId);
}

export function resumeRun(db, runId, { ownerPid = process.pid } = {}) {
  const run = getRun(db, runId);
  if (!run) throw new RotationError("UNKNOWN_RUN", `unknown run ${runId}`);
  if (!["paused", "interrupted", "failed"].includes(run.status)) {
    throw new RotationError("RUN_NOT_RESUMABLE", `run is ${run.status}`);
  }
  const src = getKeyRecord(db, run.from_key_id);
  const dst = getKeyRecord(db, run.to_key_id);
  if (!src || src.status === "destroyed") {
    throw new RotationError("SOURCE_KEY_DESTROYED", "source key is gone; rollback is impossible");
  }
  if (!dst || dst.status === "destroyed") {
    throw new RotationError("TARGET_KEY_DESTROYED", "target key is gone");
  }
  transaction(db, () => {
    db.prepare(
      "UPDATE runs SET status = 'running', heartbeat_at = ?, owner = ?, owner_pid = ?, owner_host = ?, error = NULL WHERE id = ?",
    ).run(nowIso(), ownerTag(), ownerPid, HOST, runId);
    logRun(db, runId, "info", "run resumed from row cursor", { lastRowId: run.last_row_id });
  });
  return getRun(db, runId);
}

/**
 * Roll back a run from its backup table. Uses the same chunked, resumable
 * cursor pattern. Conflict policy:
 *   - if the live row's ciphertext equals the backup pre-image, restore it
 *   - if the live row already has the source key id (someone else restored it),
 *     count as a skip
 *   - otherwise record a conflict and leave the live row untouched (never
 *     overwrite a write we cannot prove is ours)
 * Rollback never deletes the live row; it replaces only the migrated column.
 */
const ROLLBACKABLE = ["failed", "interrupted", "paused", "rollback_interrupted", "rolling_back", "completed"];

export function rollbackChunk(db, keyringDir, runId, { chunkSize = 50 } = {}) {
  const run = getRun(db, runId);
  if (!run) throw new RotationError("UNKNOWN_RUN", `unknown run ${runId}`);
  if (!ROLLBACKABLE.includes(run.status)) {
    throw new RotationError("RUN_NOT_ROLLBACKABLE", `run is ${run.status}`);
  }
  if (run.status !== "rolling_back" && run.status !== "rollback_interrupted") {
    // The partial unique index allows only one live run. Rolling back a
    // completed run while another rotation is live would violate it, so refuse
    // early with a clear reason instead of a constraint error.
    const other = db
      .prepare(
        `SELECT id FROM runs WHERE id != ? AND status IN
         ('running','paused','interrupted','verifying','rolling_back','rollback_interrupted','failed') LIMIT 1`,
      )
      .get(runId);
    if (other) {
      throw new RotationError("ANOTHER_RUN_LIVE", `another run is live: ${other.id}`, { runId: other.id });
    }
  }
  if (!run.backup_table || !tableExists(db, run.backup_table, BACKUP_TABLE_RE)) {
    throw new RotationError("NO_BACKUP", "backup table is missing; cannot roll back");
  }
  let src;
  try {
    src = loadKeyForMigration(db, keyringDir, run.from_key_id);
  } catch (err) {
    throw new RotationError("SOURCE_KEY_UNAVAILABLE", err.message, { cause: err.code });
  }
  // The target key is not needed for rollback: ownership is proven by the
  // recorded ciphertext hashes, not by re-decrypting. This means rollback still
  // works if the target key was destroyed after the failed run.

  const result = transaction(db, () => {
    const fresh = getRun(db, runId);
    if (!ROLLBACKABLE.includes(fresh.status)) {
      throw new RotationError("RUN_NOT_ROLLBACKABLE", `run state changed to ${fresh.status}`);
    }
    db.prepare("UPDATE runs SET status = 'rolling_back', heartbeat_at = ? WHERE id = ?").run(nowIso(), runId);
    const rows = db
      .prepare(
        `SELECT b.id AS id, b.${run.column_name} AS backup_v, e.${run.column_name} AS live_v
         FROM ${fresh.backup_table} b JOIN events e ON e.id = b.id
         WHERE b.id > ? ORDER BY b.id ASC LIMIT ?`,
      )
      .all(fresh.rollback_last_row_id, chunkSize);
    if (rows.length === 0) {
      db.prepare(
        "UPDATE runs SET status = 'rolled_back', finished_at = ?, heartbeat_at = ? WHERE id = ?",
      ).run(nowIso(), nowIso(), runId);
      logRun(db, runId, "info", "rollback complete; backup retained for audit", {
        restored: fresh.rollback_restored,
        conflicts: fresh.rollback_conflicts,
      });
      return { done: true, restored: 0, conflicts: 0, skipped: 0, lastRowId: fresh.rollback_last_row_id };
    }
    let restored = 0;
    let conflicts = 0;
    let skipped = 0;
    let lastId = fresh.rollback_last_row_id;
    const touchedStmt = db.prepare(
      "SELECT wrote_hash FROM run_touched WHERE run_id = ? AND row_id = ?",
    );
    for (const row of rows) {
      lastId = row.id;
      const backupEnv = decodeBlob(row.backup_v);
      const liveEnv = decodeBlob(row.live_v);
      if (!backupEnv) {
        skipped += 1;
        continue;
      }
      if (liveEnv && liveEnv.equals(backupEnv)) {
        skipped += 1; // already at pre-image
        continue;
      }
      if (liveEnv == null) {
        // Nulled by an outside writer after our migration; do not resurrect.
        conflicts += 1;
        recordConflict(db, runId, row.id, "live_value_null");
        continue;
      }
      // Ownership proof: we recorded the exact ciphertext byte hash of every
      // row this run wrote. Only restore if the live bytes are still that write.
      const touched = touchedStmt.get(runId, row.id);
      const liveKey = envelopeKeyId(liveEnv);
      if (!touched || touched.wrote_hash !== ciphertextHash(liveEnv)) {
        conflicts += 1;
        recordConflict(db, runId, row.id, touched ? "live_row_changed" : "not_written_by_run");
        continue;
      }
      if (liveKey !== run.to_key_id) {
        conflicts += 1;
        recordConflict(db, runId, row.id, "unexpected_live_key");
        continue;
      }
      // The backup pre-image must still be readable under the source key; if it
      // is not, the backup is unusable and rollback must stop, not guess.
      try {
        decryptValue(backupEnv, {
          key: src.key,
          purpose: run.purpose,
          rowId: row.id,
          column: run.column_name,
        });
      } catch (err) {
        throw new RotationError("BACKUP_UNREADABLE", `backup row ${row.id} is unreadable`, {
          rowId: row.id,
          cause: err.code,
        });
      }
      db.prepare(`UPDATE events SET ${run.column_name} = ? WHERE id = ?`).run(
        encodeBlob(Buffer.from(backupEnv)),
        row.id,
      );
      restored += 1;
    }
    db.prepare(
      `UPDATE runs SET rollback_last_row_id = ?, rollback_processed_rows = rollback_processed_rows + ?,
                      rollback_restored = rollback_restored + ?, rollback_conflicts = rollback_conflicts + ?,
                      heartbeat_at = ? WHERE id = ?`,
    ).run(lastId, rows.length, restored, conflicts, nowIso(), runId);
    return { done: false, restored, conflicts, skipped, lastRowId: lastId };
  });
  return result;
}

export function dropRunBackup(db, runId) {
  const run = getRun(db, runId);
  if (!run) throw new RotationError("UNKNOWN_RUN", `unknown run ${runId}`);
  if (run.status !== "completed" && run.status !== "rolled_back") {
    throw new RotationError("RUN_NOT_TERMINAL", "backup can only be dropped after completion or rollback");
  }
  const table = run.backup_table;
  if (!table) return { dropped: false, table: null };
  if (!BACKUP_TABLE_RE.test(table)) throw new RotationError("BAD_BACKUP", "invalid backup table name");
  const remaining = countRowsUnderKeyEverywhere(db, run.purpose, run.from_key_id);
  // Before dropping, ensure no rows anywhere still need this backup: live table
  // must have no rows under the source key for a completed run.
  if (run.status === "completed" && remaining > 0) {
    const liveRemaining = countRowsUnderKey(db, run.purpose, run.from_key_id);
    if (liveRemaining > 0) {
      throw new RotationError(
        "SOURCE_ROWS_REMAIN",
        `${liveRemaining} live row(s) still under source key; cannot drop backup`,
      );
    }
  }
  transaction(db, () => {
    dropTable(db, table, BACKUP_TABLE_RE);
    db.prepare("UPDATE runs SET backup_table = NULL, backup_dropped_at = ? WHERE id = ?").run(nowIso(), runId);
    logRun(db, runId, "info", "backup table dropped", { table });
  });
  return { dropped: true, table };
}

/**
 * Enable the staged key as active after a completed run. Retiring key gets a
 * grace window; old material stays readable until destroy conditions pass.
 */
export function finalizeRun(db, runId) {
  const run = getRun(db, runId);
  if (!run) throw new RotationError("UNKNOWN_RUN", `unknown run ${runId}`);
  if (run.status !== "completed") throw new RotationError("RUN_NOT_COMPLETED", `run is ${run.status}`);
  const dst = getKeyRecord(db, run.to_key_id);
  if (!dst) throw new RotationError("UNKNOWN_KEY", "target key missing");
  return dst;
}

/**
 * Abandon a failed run without rollback. Only allowed when the operator has
 * explicitly accepted the partial state; backup is kept (never dropped), and
 * the slot is freed by moving to "abandoned".
 */
export function abandonFailedRun(db, runId, { note = "" } = {}) {
  const run = getRun(db, runId);
  if (!run) throw new RotationError("UNKNOWN_RUN", `unknown run ${runId}`);
  if (run.status !== "failed") {
    throw new RotationError("RUN_NOT_FAILED", "only failed runs can be abandoned");
  }
  db.prepare("UPDATE runs SET status = 'abandoned', finished_at = ? WHERE id = ?").run(nowIso(), runId);
  logRun(db, runId, "warn", "failed run abandoned; backup retained", { note });
  return getRun(db, runId);
}

export function runSummary(db, runId) {
  const run = getRun(db, runId);
  if (!run) return null;
  const dist = {};
  const rows = db.prepare(`SELECT ${run.column_name} AS v FROM events WHERE ${run.column_name} IS NOT NULL`).all();
  for (const row of rows) {
    const buf = Buffer.isBuffer(row.v) ? row.v : Buffer.from(row.v);
    const kid = tryEnvelopeKeyId(buf) ?? "corrupt";
    dist[kid] = (dist[kid] || 0) + 1;
  }
  const backupRows =
    run.backup_table && BACKUP_TABLE_RE.test(run.backup_table)
      ? tableExists(db, run.backup_table, BACKUP_TABLE_RE)
        ? countRows(db, run.backup_table)
        : 0
      : 0;
  return {
    ...run,
    progress: run.total_rows ? Math.min(100, Math.round((run.processed_rows / run.total_rows) * 100)) : 0,
    distribution: dist,
    backupRows,
    log: runLog(db, runId, 100),
  };
}

// Imported late to keep the chunk scanner readable; aliasing avoids confusion.
import { countRowsUnderKey } from "./keyring.js";

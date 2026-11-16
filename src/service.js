// src/service.js
// Application service layer: seeded fictional data, write path, read path with
// per-purpose leases and an in-memory plaintext cache, rotation orchestration,
// and key lifecycle actions.

import { randomInt } from "node:crypto";
import { nowIso } from "./config.js";
import {
  COLUMNS,
  COLUMN_TO_PURPOSE,
  ENCRYPTED_COLUMNS,
  PURPOSE_TO_COLUMN,
  PURPOSES,
} from "./schema.js";
import {
  countRows,
  encodeBlob,
  decodeBlob,
  backupTableName,
  transaction,
  listBackupTables,
  listShadowTables,
} from "./db.js";
import {
  decryptValue,
  encryptValue,
  envelopeKeyId,
  envelopePurpose,
  tryEnvelopeKeyId,
} from "./crypto.js";
import {
  activeKeyForPurpose,
  createKey,
  destroyKey,
  destructionReadiness,
  getKeyRecord,
  keyringManifest,
  listKeys,
  loadKeyForRead,
  loadKeyForWrite,
  loadKeyForMigration,
  promoteKey,
  purposeState,
  revokePurpose,
  restorePurpose,
  KeyringError,
} from "./keyring.js";
import {
  acquireLease,
  releaseLease,
  leaseSummary,
  activeLeasesForPurpose,
  activeLeasesForKey,
} from "./leases.js";
import { PlaintextCache } from "./cache.js";
import {
  findLiveRun,
  getRun,
  startRun,
  migrateChunk,
  verifyChunk,
  pauseRun,
  resumeRun,
  rollbackChunk,
  dropRunBackup,
  abandonFailedRun,
  runSummary,
  reconcileRuns,
  logRun,
  RotationError,
} from "./rotation.js";
import { PROCESS_TAG, hostTag } from "./identity.js";

export class ServiceError extends Error {
  constructor(code, message, details = {}, status = 400) {
    super(message);
    this.name = "ServiceError";
    this.code = code;
    Object.assign(this, details);
    this.status = status;
  }
}

const REGIONS = ["华东", "华南", "华北", "西南", "东北"];
const PLANS = ["free", "pro", "team", "enterprise"];
const FIRST = ["lin", "chen", "wang", "zhao", "sun", "zhou", "wu", "zheng", "feng", "chu"];
const LAST = ["xia", "yu", "hao", "ran", "ning", "kai", "jun", "yi", "meng", "qing"];

function fictionalEmail(i) {
  const a = FIRST[i % FIRST.length];
  const b = LAST[Math.floor(i / FIRST.length) % LAST.length];
  return `${a}.${b}${String(i).padStart(4, "0")}@example.test`;
}

function fictionalSession(i) {
  return `sess-${(i * 2654435761 % 0xffffffff).toString(16).padStart(8, "0")}`;
}

function fictionalAudit(i) {
  return `audit://fictional/${String(100000 + i)}`;
}

function plaintextForColumn(column, i) {
  if (column === "customer_email") return fictionalEmail(i);
  if (column === "session_label") return fictionalSession(i);
  if (column === "audit_ref") return fictionalAudit(i);
  throw new Error(`no generator for ${column}`);
}

export class WorkbenchService {
  constructor({ db, config, cache = null }) {
    this.db = db;
    this.config = config;
    this.cache = cache || new PlaintextCache({ maxEntries: config.cacheMaxEntries });
    this.startedAt = nowIso();
    this.instanceId = PROCESS_TAG;
    this.processId = process.pid;
    this.reconciled = reconcileRuns(db);
  }

  // ---------- bootstrap ----------

  bootstrap({ rowCount = 240, rotateSome = true, graceSeconds = this.config.graceSeconds } = {}) {
    const existing = countRows(this.db, "events");
    if (existing > 0) {
      return { seeded: false, rows: existing, manifest: this.manifest() };
    }
    if (!PURPOSES.every((p) => activeKeyForPurpose(this.db, p))) {
      for (const purpose of PURPOSES) {
        if (!activeKeyForPurpose(this.db, purpose)) {
          createKey(this.db, this.config.keyringDir, {
            purpose,
            label: `${purpose}-initial`,
            activate: true,
          });
        }
      }
    }
    const n = Math.max(1, Math.min(Number(rowCount) || 240, 5000));
    const started = Date.now();
    for (let i = 1; i <= n; i += 1) {
      const occurredAt = new Date(Date.UTC(2026, 0, 1) + i * 37 * 60 * 1000).toISOString();
      const region = REGIONS[i % REGIONS.length];
      const plan = PLANS[i % PLANS.length];
      const revenue = 100 + ((i * 7919) % 90000);
      const row = {
        occurred_at: occurredAt,
        region,
        plan,
        revenue_minor: revenue,
      };
      for (const column of ENCRYPTED_COLUMNS) {
        const purpose = COLUMN_TO_PURPOSE[column];
        const { key, record } = loadKeyForWrite(this.db, this.config.keyringDir, purpose);
        row[column] = encodeBlob(
          encryptValue(plaintextForColumn(column, i), {
            key,
            keyId: record.key_id,
            purpose,
            rowId: i,
            column,
          }),
        );
      }
      this.db
        .prepare(
          `INSERT INTO events(id, occurred_at, region, plan, revenue_minor, customer_email, session_label, audit_ref)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          i,
          row.occurred_at,
          row.region,
          row.plan,
          row.revenue_minor,
          row.customer_email,
          row.session_label,
          row.audit_ref,
        );
    }
    this.db
      .prepare("INSERT INTO meta(key, value) VALUES ('seeded_rows', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(String(n));
    if (rotateSome && n >= 40) {
      // Stage a second generation for both encrypted-by-policy purposes and cut
      // writes over to it. Then backfill only part of the pii column so readers
      // immediately meet both generations; analytics also mixes generations
      // because writes after cutover already use gen2.
      for (const purpose of ["pii", "analytics"]) {
        const prev = activeKeyForPurpose(this.db, purpose);
        const staged = createKey(this.db, this.config.keyringDir, {
          purpose,
          label: `${purpose}-gen2`,
        });
        promoteKey(this.db, this.config.keyringDir, staged.key_id, { graceSeconds });
        if (purpose === "pii") {
          const run = startRun(this.db, this.config.keyringDir, {
            purpose,
            fromKeyId: prev.key_id,
            toKeyId: staged.key_id,
            chunkSize: 20,
          });
          this.migratePrefix(run.id, Math.floor(n / 2));
        }
      }
      // New writes land under gen2 for every purpose, producing a natural
      // two-generation read mix without touching the paused run.
      for (let i = 0; i < Math.min(6, Math.floor(n / 10)); i += 1) {
        this.createEvent({});
      }
    }
    this.cache.clear();
    return {
      seeded: true,
      rows: n,
      elapsedMs: Date.now() - started,
      manifest: this.manifest(),
    };
  }

  /** Drive an already-started run to completion without waiting on HTTP. */
  driveRun(runId, { chunkSize } = {}) {
    let guard = 0;
    for (;;) {
      const run = getRun(this.db, runId);
      if (!run) throw new ServiceError("UNKNOWN_RUN", "run vanished", {}, 500);
      if (run.status === "running") {
        migrateChunk(this.db, this.config.keyringDir, runId, { chunkSize });
      } else if (run.status === "verifying") {
        verifyChunk(this.db, this.config.keyringDir, runId, { chunkSize: 200 });
      } else {
        return getRun(this.db, runId);
      }
      guard += 1;
      if (guard > 100_000) throw new ServiceError("RUNAWAY", "run did not terminate", {}, 500);
    }
  }

  /** Migrate exactly `count` rows, pausing mid-table for the demo. */
  migratePrefix(runId, count) {
    let done = 0;
    while (done < count) {
      const run = getRun(this.db, runId);
      if (run.status !== "running") break;
      const step = Math.min(run.chunk_size, count - done);
      migrateChunk(this.db, this.config.keyringDir, runId, { chunkSize: step });
      done += step;
    }
    if (getRun(this.db, runId).status === "running") pauseRun(this.db, runId);
    return getRun(this.db, runId);
  }

  // ---------- write path ----------

  createEvent({ occurredAt, region, plan, revenueMinor, customerEmail, sessionLabel, auditRef }) {
    const at = occurredAt || nowIso();
    const values = {
      customer_email: customerEmail ?? fictionalEmail(randomInt(1, 1_000_000)),
      session_label: sessionLabel ?? fictionalSession(randomInt(1, 1_000_000)),
      audit_ref: auditRef ?? fictionalAudit(randomInt(1, 1_000_000)),
    };
    // The row id is part of the AAD, so it must be final before encryption.
    // Reserve the id by inserting clear columns first, then encrypt with the
    // real rowid inside the same transaction. Encrypting against a guessed
    // MAX(id)+1 could bind a row to the wrong id under concurrency and make it
    // permanently undecryptable.
    const id = transaction(this.db, () => {
      for (const column of ENCRYPTED_COLUMNS) {
        const purpose = COLUMN_TO_PURPOSE[column];
        const state = purposeState(this.db, purpose);
        if (state?.revokedAt) {
          throw new ServiceError("PURPOSE_REVOKED", `purpose ${purpose} is revoked; refusing new writes`, {
            purpose,
          });
        }
        if (!activeKeyForPurpose(this.db, purpose)) {
          throw new ServiceError("NO_ACTIVE_KEY", `no active key for purpose ${purpose}`, {}, 409);
        }
      }
      const info = this.db
        .prepare(
          `INSERT INTO events(occurred_at, region, plan, revenue_minor, customer_email, session_label, audit_ref)
           VALUES (?, ?, ?, ?, NULL, NULL, NULL)`,
        )
        .run(
          at,
          region || REGIONS[randomInt(0, REGIONS.length)],
          plan || PLANS[randomInt(0, PLANS.length)],
          Number(revenueMinor) || 1000,
        );
      const rowId = Number(info.lastInsertRowid);
      for (const column of ENCRYPTED_COLUMNS) {
        const purpose = COLUMN_TO_PURPOSE[column];
        const { key, record } = loadKeyForWrite(this.db, this.config.keyringDir, purpose);
        const env = encryptValue(String(values[column]), {
          key,
          keyId: record.key_id,
          purpose,
          rowId,
          column,
        });
        this.db.prepare(`UPDATE events SET ${column} = ? WHERE id = ?`).run(encodeBlob(env), rowId);
      }
      return rowId;
    });
    return this.readEvent(id);
  }

  readEvent(id) {
    const row = this.db
      .prepare("SELECT id, occurred_at, region, plan, revenue_minor, customer_email, session_label, audit_ref FROM events WHERE id = ?")
      .get(id);
    if (!row) return null;
    const out = {
      id: row.id,
      occurred_at: row.occurred_at,
      region: row.region,
      plan: row.plan,
      revenue_minor: row.revenue_minor,
      encrypted: {},
      values: {},
    };
    for (const column of ENCRYPTED_COLUMNS) {
      const env = decodeBlob(row[column]);
      out.encrypted[column] = env ? envelopeKeyId(env) : null;
      if (!env) {
        out.values[column] = null;
        continue;
      }
      try {
        out.values[column] = this.readValue({ rowId: row.id, column }).plaintext;
      } catch (err) {
        out.values[column] = null;
        out.errors = out.errors || {};
        out.errors[column] = err.code || "READ_FAILED";
      }
    }
    return out;
  }

  /**
   * Re-encrypt one column of one row under the active key. Used by the write
   * path to demonstrate that live writers never hold stale keys. A retired key
   * is still required to read the old value.
   */
  rewriteEvent(rowId, column) {
    if (!COLUMN_TO_PURPOSE[column]) {
      throw new ServiceError("BAD_COLUMN", `unknown encrypted column`);
    }
    const purpose = COLUMN_TO_PURPOSE[column];
    const state = purposeState(this.db, purpose);
    if (state?.revokedAt) {
      throw new ServiceError("PURPOSE_REVOKED", `purpose ${purpose} is revoked; refusing writes`);
    }
    const row = this.db.prepare(`SELECT id, ${column} AS v FROM events WHERE id = ?`).get(rowId);
    if (!row) throw new ServiceError("NOT_FOUND", `event ${rowId} not found`, {}, 404);
    const oldKeyId = envelopeKeyId(decodeBlob(row.v));
    const oldKey = loadKeyForRead(this.db, this.config.keyringDir, oldKeyId, purpose);
    const plaintext = decryptValue(decodeBlob(row.v), {
      key: oldKey,
      purpose,
      rowId,
      column,
    });
    const { key, record } = loadKeyForWrite(this.db, this.config.keyringDir, purpose);
    const next = encryptValue(plaintext, {
      key,
      keyId: record.key_id,
      purpose,
      rowId,
      column,
    });
    this.db.prepare(`UPDATE events SET ${column} = ? WHERE id = ?`).run(encodeBlob(next), rowId);
    return { rowId, column, fromKeyId: oldKeyId, toKeyId: record.key_id };
  }

  // ---------- read path ----------

  /**
   * Read one encrypted value. A short-lived query lease is taken before key
   * use and released after; cache hits do not need a lease but are still
   * validated against revocation and key status.
   */
  readValue({ rowId, column, useCache = true, leaseTtlMs = this.config.queryLeaseTtlMs }) {
    if (!COLUMN_TO_PURPOSE[column]) {
      throw new ServiceError("BAD_COLUMN", `unknown encrypted column`, {}, 400);
    }
    const purpose = COLUMN_TO_PURPOSE[column];
    const state = purposeState(this.db, purpose);
    if (state?.revokedAt) {
      this.cache.purgePurpose(purpose);
      throw new ServiceError("PURPOSE_REVOKED", `purpose ${purpose} is revoked; reads are refused`, {
        purpose,
        revokedAt: state.revokedAt,
      }, 403);
    }
    const row = this.db.prepare(`SELECT id, ${column} AS v FROM events WHERE id = ?`).get(rowId);
    if (!row) throw new ServiceError("NOT_FOUND", `event ${rowId} not found`, {}, 404);
    const env = decodeBlob(row.v);
    if (!env) {
      return { rowId, column, purpose, plaintext: null, keyId: null, source: "null" };
    }
    const keyId = envelopeKeyId(env);
    const envPurpose = envelopePurpose(env);
    if (envPurpose !== purpose) {
      throw new ServiceError("COLUMN_PURPOSE_MISMATCH", `ciphertext purpose ${envPurpose} does not match column ${column}`, {}, 500);
    }
    const rec = getKeyRecord(this.db, keyId);
    const cached = useCache
      ? this.cache.get({
          purpose,
          column,
          rowId,
          keyId,
          keyStatus: rec?.status,
          revoked: Boolean(state?.revokedAt),
        })
      : null;
    if (cached != null) {
      return { rowId, column, purpose, plaintext: cached, keyId, source: "cache" };
    }
    const lease = acquireLease(this.db, {
      kind: "query",
      holder: this.instanceId,
      keyId,
      purpose,
      column,
      ttlMs: leaseTtlMs,
    });
    try {
      const key = loadKeyForRead(this.db, this.config.keyringDir, keyId, purpose);
      const plaintext = decryptValue(env, { key, purpose, rowId, column });
      this.cache.set({ purpose, column, rowId, keyId, plaintext });
      return { rowId, column, purpose, plaintext, keyId, source: "db", leaseId: lease.id };
    } finally {
      releaseLease(this.db, lease.id);
    }
  }

  listEvents({ limit = 20, offset = 0, decrypt = true } = {}) {
    const lim = Math.max(1, Math.min(Number(limit) || 20, 100));
    const off = Math.max(0, Number(offset) || 0);
    const rows = this.db
      .prepare(`SELECT id, occurred_at, region, plan, revenue_minor, customer_email, session_label, audit_ref
                FROM events ORDER BY id ASC LIMIT ? OFFSET ?`)
      .all(lim, off);
    const total = countRows(this.db, "events");
    const items = rows.map((row) => {
      const out = {
        id: row.id,
        occurred_at: row.occurred_at,
        region: row.region,
        plan: row.plan,
        revenue_minor: row.revenue_minor,
        encrypted: {},
        values: {},
      };
      for (const column of ENCRYPTED_COLUMNS) {
        const env = decodeBlob(row[column]);
        out.encrypted[column] = env ? envelopeKeyId(env) : null;
        if (!decrypt) continue;
        if (!env) {
          out.values[column] = null;
          continue;
        }
        try {
          out.values[column] = this.readValue({ rowId: row.id, column }).plaintext;
        } catch (err) {
          out.values[column] = null;
          out.errors = out.errors || {};
          out.errors[column] = err.code || "READ_FAILED";
        }
      }
      return out;
    });
    return { total, limit: lim, offset: off, items };
  }

  /** Read distribution by key id per column, computed from envelopes only. */
  keyDistribution() {
    const out = {};
    for (const column of ENCRYPTED_COLUMNS) {
      const rows = this.db.prepare(`SELECT ${column} AS v FROM events WHERE ${column} IS NOT NULL`).all();
      const counts = {};
      for (const row of rows) {
        const buf = Buffer.isBuffer(row.v) ? row.v : Buffer.from(row.v);
        const kid = tryEnvelopeKeyId(buf) ?? "corrupt";
        counts[kid] = (counts[kid] || 0) + 1;
      }
      out[column] = counts;
    }
    return out;
  }

  // ---------- key lifecycle ----------

  createKeyForPurpose({ purpose, label, activate = false }) {
    if (!PURPOSE_TO_COLUMN[purpose]) throw new ServiceError("BAD_PURPOSE", `unknown purpose ${purpose}`);
    if (purposeState(this.db, purpose)?.revokedAt) {
      throw new ServiceError("PURPOSE_REVOKED", `restore purpose ${purpose} before creating a key`);
    }
    const rec = createKey(this.db, this.config.keyringDir, { purpose, label, activate });
    this.cache.purgePurpose(purpose);
    return rec;
  }

  promote({ keyId, graceSeconds = this.config.graceSeconds }) {
    const rec = getKeyRecord(this.db, keyId);
    if (!rec) throw new ServiceError("UNKNOWN_KEY", `unknown key ${keyId}`, {}, 404);
    if (purposeState(this.db, rec.purpose)?.revokedAt) {
      throw new ServiceError("PURPOSE_REVOKED", "cannot promote a key for a revoked purpose");
    }
    const result = promoteKey(this.db, this.config.keyringDir, keyId, { graceSeconds });
    // The retiring key must still decrypt in-flight reads; do not purge here.
    return result;
  }

  destroy({ keyId, graceSeconds = this.config.graceSeconds }) {
    const rec = getKeyRecord(this.db, keyId);
    if (!rec) throw new ServiceError("UNKNOWN_KEY", `unknown key ${keyId}`, {}, 404);
    try {
      const result = destroyKey(this.db, this.config.keyringDir, keyId, { graceSeconds });
      this.cache.purgeKey(keyId);
      return result;
    } catch (err) {
      if (err instanceof KeyringError) {
        throw new ServiceError(err.code, err.message, { reasons: err.reasons || [] }, 409);
      }
      throw err;
    }
  }

  revoke(purpose) {
    if (!PURPOSE_TO_COLUMN[purpose]) throw new ServiceError("BAD_PURPOSE", `unknown purpose ${purpose}`);
    const result = revokePurpose(this.db, purpose);
    // Revocation invalidates cached plaintext immediately, and new reads are
    // refused above. Existing leases are not force-released: a query already
    // issued may finish, but any later read is denied and the cache is gone.
    const purged = this.cache.purgePurpose(purpose);
    const leases = activeLeasesForPurpose(this.db, purpose);
    return { ...result, cachePurged: purged, activeLeases: leases.length, leases };
  }

  restore(purpose) {
    if (!PURPOSE_TO_COLUMN[purpose]) throw new ServiceError("BAD_PURPOSE", `unknown purpose ${purpose}`);
    const result = restorePurpose(this.db, purpose);
    this.cache.purgePurpose(purpose);
    return result;
  }

  // ---------- rotation orchestration ----------

  /**
   * Rotation sequence (in-place strategy):
   *   1. stage a new key for the purpose (if not supplied)
   *   2. activate it — from this instant every new write uses the new key
   *   3. start the backfill run that walks old-key rows forward
   * The window between 2 and 3 is safe: new rows are already under the target
   * key, and the walk skips any row that already carries it.
   */
  /**
   * Rotation planner. Two cases:
   *
   *  A. The column still has rows under an older generation while a newer key is
   *     already active (the write cutover happened, the backfill did not finish).
   *     Target = the active key; source = the older generation. No new key.
   *  B. Every row is already under the active key. Stage + activate a new key,
   *     then backfill from the old active key to it.
   *
   * In both cases exactly one source generation is allowed. More than one older
   * generation (e.g. an abandoned half-rotation from two generations ago) is
   * refused up front with the offending key ids, rather than failing mid-walk.
   */
  startRotation({ purpose, chunkSize = this.config.defaultChunkSize, strategy, fromKeyId, toKeyId }) {
    if (!PURPOSE_TO_COLUMN[purpose]) throw new ServiceError("BAD_PURPOSE", `unknown purpose ${purpose}`);
    if (purposeState(this.db, purpose)?.revokedAt) {
      throw new ServiceError("PURPOSE_REVOKED", `purpose ${purpose} is revoked`, {}, 409);
    }
    const column = PURPOSE_TO_COLUMN[purpose];
    const rowKeyIds = new Set(
      this.db
        .prepare(`SELECT ${column} AS v FROM events WHERE ${column} IS NOT NULL`)
        .all()
        .map((r) => tryEnvelopeKeyId(decodeBlob(r.v)))
        .filter(Boolean),
    );
    const active = activeKeyForPurpose(this.db, purpose);

    let from;
    let to;

    if (fromKeyId || toKeyId) {
      from = fromKeyId ? getKeyRecord(this.db, fromKeyId) : null;
      to = toKeyId ? getKeyRecord(this.db, toKeyId) : null;
      if (!from || !to) throw new ServiceError("UNKNOWN_KEY", "explicit source/target key not found", {}, 404);
    } else {
      const older = [...rowKeyIds].filter((id) => id !== active?.key_id).sort();
      if (older.length > 1) {
        throw new ServiceError(
          "MULTI_GENERATION_REMAINING",
          `column ${column} holds rows under several older keys (${older.join(", ")}); finish the older rotation first`,
          { keyIds: older },
          409,
        );
      }
      if (active && older.length === 1) {
        // Case A: resume the unfinished backfill onto the already-active key.
        from = getKeyRecord(this.db, older[0]);
        to = active;
      } else {
        // Case B: full rotation to a fresh generation.
        from = active;
        if (!from) throw new ServiceError("NO_ACTIVE_KEY", `no active key for purpose ${purpose}`, {}, 409);
        to =
          this.db
            .prepare("SELECT * FROM keyring WHERE purpose = ? AND status = 'staged' ORDER BY key_id ASC LIMIT 1")
            .get(purpose) ??
          createKey(this.db, this.config.keyringDir, {
            purpose,
            label: `${purpose}-gen${Date.now() % 10000}`,
          });
        if (to.status === "staged") {
          promoteKey(this.db, this.config.keyringDir, to.key_id, { graceSeconds: this.config.graceSeconds });
        }
        to = getKeyRecord(this.db, to.key_id);
      }
    }

    if (!from || !to) throw new ServiceError("UNKNOWN_KEY", "source or target key is missing", {}, 404);
    if (from.purpose !== purpose || to.purpose !== purpose) {
      throw new ServiceError("PURPOSE_MISMATCH", "source/target key belongs to another purpose", {}, 409);
    }
    if (from.key_id === to.key_id) {
      throw new ServiceError("SAME_KEY", "source and target keys are identical", {}, 409);
    }
    if (to.status !== "active") {
      throw new ServiceError("TARGET_NOT_ACTIVE", `target key is ${to.status}; activate it first`, {}, 409);
    }
    try {
      return startRun(this.db, this.config.keyringDir, {
        purpose,
        fromKeyId: from.key_id,
        toKeyId: to.key_id,
        chunkSize: Math.max(1, Math.min(Number(chunkSize) || this.config.defaultChunkSize, this.config.maxChunkSize)),
        strategy: strategy || "in_place_chunked",
      });
    } catch (err) {
      if (err instanceof RotationError) {
        throw new ServiceError(err.code, err.message, { ...err }, 409);
      }
      throw err;
    }
  }

  rotateStep(runId, { chunkSize, phase } = {}) {
    const run = getRun(this.db, runId);
    if (!run) throw new ServiceError("UNKNOWN_RUN", `unknown run ${runId}`, {}, 404);
    if (run.status === "running") {
      try {
        return { phase: "migrate", ...migrateChunk(this.db, this.config.keyringDir, runId, { chunkSize }) };
      } catch (err) {
        if (err instanceof RotationError) {
          throw new ServiceError(err.code, err.message, { ...err }, 409);
        }
        throw err;
      }
    }
    if (run.status === "verifying" || phase === "verify") {
      return { phase: "verify", ...verifyChunk(this.db, this.config.keyringDir, runId, { chunkSize: 100 }) };
    }
    throw new ServiceError("RUN_NOT_RUNNING", `run is ${run.status}`, {}, 409);
  }

  runAll(runId, { maxChunks = 10_000 } = {}) {
    let chunks = 0;
    for (;;) {
      const run = getRun(this.db, runId);
      if (!run) throw new ServiceError("UNKNOWN_RUN", "unknown run", {}, 404);
      if (run.status !== "running" && run.status !== "verifying") {
        return { run: runSummary(this.db, runId), chunks };
      }
      this.rotateStep(runId);
      chunks += 1;
      if (chunks > maxChunks) throw new ServiceError("RUNAWAY", "too many chunks", {}, 500);
    }
  }

  pause(runId) {
    try {
      return pauseRun(this.db, runId);
    } catch (err) {
      if (err instanceof RotationError) throw new ServiceError(err.code, err.message, {}, 409);
      throw err;
    }
  }

  resume(runId) {
    try {
      return resumeRun(this.db, runId);
    } catch (err) {
      if (err instanceof RotationError) throw new ServiceError(err.code, err.message, {}, 409);
      throw err;
    }
  }

  rollback(runId) {
    const maxChunks = 10_000;
    let chunks = 0;
    for (;;) {
      const res = rollbackChunk(this.db, this.config.keyringDir, runId, { chunkSize: 50 });
      chunks += 1;
      if (res.done) {
        this.cache.clear();
        return { ...res, run: runSummary(this.db, runId), chunks };
      }
      if (chunks > maxChunks) throw new ServiceError("RUNAWAY", "rollback did not terminate", {}, 500);
    }
  }

  dropBackup(runId) {
    try {
      return dropRunBackup(this.db, runId);
    } catch (err) {
      if (err instanceof RotationError) throw new ServiceError(err.code, err.message, {}, 409);
      throw err;
    }
  }

  abandon(runId, note) {
    try {
      return abandonFailedRun(this.db, runId, { note });
    } catch (err) {
      if (err instanceof RotationError) throw new ServiceError(err.code, err.message, {}, 409);
      throw err;
    }
  }

  // ---------- status ----------

  keyDestroyReadiness(keyId) {
    try {
      return destructionReadiness(this.db, keyId, { graceSeconds: this.config.graceSeconds });
    } catch (err) {
      if (err instanceof KeyringError) throw new ServiceError(err.code, err.message, {}, 404);
      throw err;
    }
  }

  status() {
    reconcileRuns(this.db);
    const live = findLiveRun(this.db);
    const keys = listKeys(this.db).map((k) => {
      let readiness = null;
      if (k.status !== "destroyed") {
        try {
          const r = destructionReadiness(this.db, k.key_id, { graceSeconds: this.config.graceSeconds });
          readiness = { ready: r.ready, reasons: r.reasons, rowsRemaining: r.rowsRemaining };
        } catch {
          readiness = { ready: false, reasons: ["readiness_unavailable"], rowsRemaining: null };
        }
      }
      return {
        keyId: k.key_id,
        purpose: k.purpose,
        label: k.label,
        fingerprint: k.fingerprint,
        status: k.status,
        createdAt: k.created_at,
        activatedAt: k.activated_at,
        retiringAt: k.retiring_at,
        destroyEligibleAt: k.destroy_eligible_at,
        destroyedAt: k.destroyed_at,
        replaces: k.replaces,
        readable: k.status !== "destroyed" && k.status !== "staged",
        readiness,
      };
    });
    const backups = listBackupTables(this.db);
    const shadows = listShadowTables(this.db);
    const leaseInfo = leaseSummary(this.db);
    const distribution = this.keyDistribution();
    return {
      app: {
        version: "1.0.0",
        processId: this.processId,
        instanceId: this.instanceId,
        startedAt: this.startedAt,
        host: hostTag(),
      },
      config: { graceSeconds: this.config.graceSeconds, dataDir: this.config.dataDir },
      purposes: this.db
        .prepare("SELECT * FROM purposes ORDER BY purpose")
        .all()
        .map((p) => ({
          purpose: p.purpose,
          column: PURPOSE_TO_COLUMN[p.purpose],
          revokedAt: p.revoked_at,
          activeKeyId: activeKeyForPurpose(this.db, p.purpose)?.key_id ?? null,
          cachedRows: this.cache.stats().byPurpose[p.purpose] || 0,
        })),
      keys,
      columns: COLUMNS,
      distribution,
      totalRows: countRows(this.db, "events"),
      liveRun: live ? runSummary(this.db, live.id) : null,
      recentRuns: this.db
        .prepare(
          "SELECT id, status, purpose, processed_rows, total_rows, verification_errors, started_at, finished_at FROM runs ORDER BY started_at DESC LIMIT 10",
        )
        .all()
        .map((r) => ({
          id: r.id,
          status: r.status,
          purpose: r.purpose,
          processedRows: r.processed_rows,
          totalRows: r.total_rows,
          verificationErrors: r.verification_errors,
          startedAt: r.started_at,
          finishedAt: r.finished_at,
        })),
      leases: leaseInfo,
      cache: this.cache.stats(),
      backups,
      shadows,
    };
  }

  manifest() {
    return keyringManifest(this.db);
  }

  getRunDetail(runId) {
    const summary = runSummary(this.db, runId);
    if (!summary) throw new ServiceError("UNKNOWN_RUN", `unknown run ${runId}`, {}, 404);
    return summary;
  }

  /** Used by the HTTP layer to distinguish "no such run" from "no such route". */
  runExists(runId) {
    return Boolean(getRun(this.db, runId));
  }

  recover() {
    const changes = reconcileRuns(this.db);
    const live = findLiveRun(this.db);
    return { reconciled: changes, liveRun: live ? getRun(this.db, live.id) : null };
  }
}

// src/leases.js
// Durable read/migration leases. A key may not be destroyed while a live lease
// for its purpose exists. Leases expire by TTL, so a crashed process cannot pin
// an old key forever; the grace period is added on top of lease expiry.

import { randomBytes } from "node:crypto";
import { nowIso } from "./config.js";
import { transaction } from "./db.js";

const LEASE_KINDS = new Set(["query", "migration", "manual"]);

export class LeaseError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "LeaseError";
    this.code = code;
    Object.assign(this, details);
  }
}

/**
 * Acquire a lease atomically with a key-usability check. The INSERT and the
 * checks run in one IMMEDIATE transaction, and key destruction also checks
 * leases inside an IMMEDIATE transaction, so the two cannot interleave: either
 * the lease exists before destruction checks (and destruction refuses), or the
 * key is already destroyed and the lease is refused.
 */
export function acquireLease(
  db,
  { kind, holder, keyId, purpose, column, runId = null, ttlMs, requireKeyUsable = true },
) {
  if (!LEASE_KINDS.has(kind)) throw new Error(`bad lease kind: ${kind}`);
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new Error("lease ttl must be positive");
  return transaction(db, () => {
    if (requireKeyUsable) {
      const key = db.prepare("SELECT status FROM keyring WHERE key_id = ?").get(keyId);
      if (!key) throw new LeaseError("UNKNOWN_KEY", `key ${keyId} is unknown`);
      if (key.status === "destroyed") {
        throw new LeaseError("KEY_DESTROYED", `key ${keyId} has been destroyed`);
      }
      if (key.status === "staged") {
        throw new LeaseError("KEY_NOT_ACTIVE", `key ${keyId} is staged and not usable`);
      }
      const purposeRow = db.prepare("SELECT revoked_at FROM purposes WHERE purpose = ?").get(purpose);
      if (purposeRow?.revoked_at) {
        throw new LeaseError("PURPOSE_REVOKED", `purpose ${purpose} is revoked`);
      }
    }
    const id = randomBytes(8).toString("hex");
    const acquiredAt = new Date();
    const expiresAt = new Date(acquiredAt.getTime() + ttlMs);
    db.prepare(
      `INSERT INTO leases(id, kind, run_id, holder, key_id, purpose, column_name, acquired_at, expires_at, released_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
    ).run(
      id,
      kind,
      runId,
      holder,
      keyId,
      purpose,
      column,
      acquiredAt.toISOString(),
      expiresAt.toISOString(),
    );
    return getLease(db, id);
  });
}

export function getLease(db, id) {  return db.prepare("SELECT * FROM leases WHERE id = ?").get(id) ?? null;
}

export function releaseLease(db, id) {
  const info = db
    .prepare("UPDATE leases SET released_at = ? WHERE id = ? AND released_at IS NULL")
    .run(nowIso(), id);
  return info.changes > 0;
}

export function renewLease(db, id, ttlMs) {
  const expiresAt = new Date(Date.now() + ttlMs).toISOString();
  const info = db
    .prepare("UPDATE leases SET expires_at = ? WHERE id = ? AND released_at IS NULL")
    .run(expiresAt, id);
  return info.changes > 0 ? getLease(db, id) : null;
}

export function activeLeases(db, now = new Date()) {
  return db
    .prepare(
      "SELECT * FROM leases WHERE released_at IS NULL AND expires_at > ? ORDER BY acquired_at ASC",
    )
    .all(now.toISOString());
}

export function activeLeasesForPurpose(db, purpose, now = new Date()) {
  return db
    .prepare(
      `SELECT * FROM leases
       WHERE released_at IS NULL AND expires_at > ? AND purpose = ?
       ORDER BY acquired_at ASC`,
    )
    .all(now.toISOString(), purpose);
}

export function activeLeasesForKey(db, keyId, now = new Date()) {
  return db
    .prepare(
      `SELECT * FROM leases
       WHERE released_at IS NULL AND expires_at > ? AND key_id = ?
       ORDER BY acquired_at ASC`,
    )
    .all(now.toISOString(), keyId);
}

/** Expired-but-unreleased rows are retained for audit; this marks them done. */
export function sweepExpiredLeases(db, now = new Date()) {
  return db
    .prepare(
      "UPDATE leases SET released_at = expires_at WHERE released_at IS NULL AND expires_at <= ?",
    )
    .run(now.toISOString()).changes;
}

export function leaseSummary(db, now = new Date()) {
  const active = activeLeases(db, now);
  return {
    activeCount: active.length,
    byPurpose: active.reduce((acc, lease) => {
      acc[lease.purpose] = (acc[lease.purpose] || 0) + 1;
      return acc;
    }, {}),
    leases: active,
  };
}

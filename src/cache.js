// src/cache.js
// In-memory plaintext cache. Plaintext is never persisted: there is deliberately
// no cache table in SQLite and no temp-file spill. Entries are bound to a key id
// and purpose, so key destruction or purpose revocation can invalidate them.

export class PlaintextCache {
  constructor({ maxEntries = 5000, ttlMs = 60_000 } = {}) {
    this.maxEntries = maxEntries;
    this.ttlMs = ttlMs;
    this.map = new Map();
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
  }

  static #key(purpose, column, rowId) {
    return `${purpose}\u0000${column}\u0000${rowId}`;
  }

  get({ purpose, column, rowId, keyId, keyStatus, revoked }) {
    if (revoked) {
      this.map.delete(PlaintextCache.#key(purpose, column, rowId));
      return null;
    }
    if (keyStatus === "destroyed" || !keyStatus) {
      this.map.delete(PlaintextCache.#key(purpose, column, rowId));
      return null;
    }
    const k = PlaintextCache.#key(purpose, column, rowId);
    const hit = this.map.get(k);
    if (!hit) {
      this.misses += 1;
      return null;
    }
    if (hit.keyId !== keyId || Date.now() - hit.at > this.ttlMs) {
      this.map.delete(k);
      this.misses += 1;
      return null;
    }
    this.hits += 1;
    // Refresh LRU position without changing insertion timestamp semantics.
    this.map.delete(k);
    this.map.set(k, hit);
    return hit.plaintext;
  }

  set({ purpose, column, rowId, keyId, plaintext, revoked }) {
    if (revoked) return;
    const k = PlaintextCache.#key(purpose, column, rowId);
    this.map.set(k, { keyId, plaintext, at: Date.now() });
    while (this.map.size > this.maxEntries) {
      const oldest = this.map.keys().next().value;
      this.map.delete(oldest);
      this.evictions += 1;
    }
  }

  purgePurpose(purpose) {
    let removed = 0;
    for (const k of [...this.map.keys()]) {
      if (k.startsWith(`${purpose}\u0000`)) {
        this.map.delete(k);
        removed += 1;
      }
    }
    return removed;
  }

  purgeKey(keyId) {
    let removed = 0;
    for (const [k, v] of [...this.map.entries()]) {
      if (v.keyId === keyId) {
        this.map.delete(k);
        removed += 1;
      }
    }
    return removed;
  }

  purgeColumn(column) {
    let removed = 0;
    for (const k of [...this.map.keys()]) {
      const parts = k.split("\u0000");
      if (parts[1] === column) {
        this.map.delete(k);
        removed += 1;
      }
    }
    return removed;
  }

  clear() {
    this.map.clear();
  }

  stats() {
    const byPurpose = {};
    for (const [k, v] of this.map) {
      const purpose = k.split("\u0000")[0];
      byPurpose[purpose] = (byPurpose[purpose] || 0) + 1;
    }
    return {
      entries: this.map.size,
      maxEntries: this.maxEntries,
      ttlMs: this.ttlMs,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      byPurpose,
    };
  }
}

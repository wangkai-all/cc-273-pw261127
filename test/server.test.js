import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveConfig } from "../src/config.js";
import { openDb, ensureSchema } from "../src/db.js";
import { WorkbenchService } from "../src/service.js";
import { createServer } from "../src/server.js";
import { encodeKeyId } from "../src/crypto.js";

async function boot({ rows = 40 } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rk-http-"));
  const config = resolveConfig({ dataDir: dir, graceSeconds: 0 });
  const db = openDb(config.dbPath);
  ensureSchema(db);
  const service = new WorkbenchService({ db, config });
  service.bootstrap({ rowCount: rows });
  const server = createServer(service);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;
  const call = async (p, opts = {}) => {
    const res = await fetch(base + p, opts);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, headers: res.headers, text, json };
  };
  const post = (p, body = {}) =>
    call(p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return {
    dir, config, db, service, server, base, call, post,
    close: async () => {
      await new Promise((resolve) => server.close(resolve));
      db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

test("status and manifest expose metadata but never key bytes", async () => {
  const wb = await boot();
  try {
    const status = await wb.call("/api/status");
    assert.equal(status.status, 200);
    assert.ok(Array.isArray(status.json.keys));
    assert.match(status.headers.get("content-type"), /application\/json/);
    assert.equal(status.headers.get("cache-control"), "no-store");
    const manifest = await wb.call("/api/manifest");
    assert.equal(manifest.status, 200);
    assert.equal(manifest.json.cipher, "AES-256-GCM");
    assert.ok(manifest.json.keys.every((k) => /^[0-9a-f]{16}$/.test(k.fingerprint) && !("key" in k)));

    // Read the actual key files and ensure their bytes never appear in an API
    // response. Encode a raw key to base64/hex and search all payloads.
    for (const file of fs.readdirSync(wb.config.keyringDir)) {
      const key = Buffer.from(fs.readFileSync(path.join(wb.config.keyringDir, file), "utf8").trim(), "base64");
      assert.equal(status.text.includes(key.toString("base64")), false);
      assert.equal(status.text.includes(key.toString("hex")), false);
      assert.equal(manifest.text.includes(key.toString("base64")), false);
    }
  } finally {
    await wb.close();
  }
});

test("rotation drives through HTTP but refuses a second concurrent run", async () => {
  const wb = await boot();
  try {
    const live = (await wb.call("/api/status")).json.liveRun;
    await wb.post(`/api/runs/${live.id}/resume`);
    const second = await wb.post("/api/runs", { purpose: "analytics", chunkSize: 5 });
    assert.equal(second.status, 409);
    assert.equal(second.json.error.code, "RUN_IN_PROGRESS");
    const all = await wb.post(`/api/runs/${live.id}/run-all`);
    assert.equal(all.status, 200);
    assert.equal(all.json.run.status, "completed");
  } finally {
    await wb.close();
  }
});

test("destroy via HTTP is blocked while a lease exists, then succeeds", async () => {
  const wb = await boot();
  try {
    const live = (await wb.call("/api/status")).json.liveRun;
    await wb.post(`/api/runs/${live.id}/resume`);
    await wb.post(`/api/runs/${live.id}/run-all`);
    const oldId = live.from_key_id;
    const lease = await wb.post("/api/leases", { purpose: "pii", keyId: oldId, ttlMs: 30_000 });
    assert.equal(lease.status, 201);
    const blocked = await wb.post(`/api/keys/${oldId}/destroy`);
    assert.equal(blocked.status, 409);
    assert.equal(blocked.json.error.code, "NOT_READY");
    assert.ok(blocked.json.error.details.reasons.some((r) => r.startsWith("active_leases")));

    await wb.call(`/api/leases/${lease.json.id}`, { method: "DELETE" });
    const drop = await wb.post(`/api/runs/${live.id}/drop-backup`);
    assert.equal(drop.status, 200, drop.text);
    const ok = await wb.post(`/api/keys/${oldId}/destroy`);
    assert.equal(ok.status, 200, ok.text);
    const again = await wb.post(`/api/keys/${oldId}/destroy`);
    assert.equal(again.status, 409);
  } finally {
    await wb.close();
  }
});

test("errors are structured and do not leak stack traces or request bodies", async () => {
  const wb = await boot();
  try {
    const bad = await wb.call("/api/read", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not json",
    });
    assert.equal(bad.status, 400);
    assert.equal(bad.json.error.code, "BAD_JSON");
    assert.equal(bad.text.includes("at "), false);

    const missing = await wb.call("/api/runs/does-not-exist");
    assert.equal(missing.status, 404);
    assert.equal(missing.json.error.code, "UNKNOWN_RUN");

    const secret = "top-secret-plaintext-should-not-echo";
    const injected = await wb.call("/api/read", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ rowId: 999999, column: secret }),
    });
    assert.equal(injected.status, 400);
    assert.equal(injected.text.includes(secret), false, "bad input is not reflected");

    const tooBig = await wb.call("/api/events", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pad: "x".repeat(300 * 1024) }),
    });
    assert.equal(tooBig.status, 413);
  } finally {
    await wb.close();
  }
});

test("static serving is confined to public/ and sets a CSP", async () => {
  const wb = await boot({ rows: 40 });
  try {
    const index = await wb.call("/");
    assert.equal(index.status, 200);
    assert.match(index.headers.get("content-security-policy"), /default-src 'self'/);
    assert.equal(index.text.includes("换钥工作台"), true);

    for (const probe of ["/../src/server.js", "/..%2Fsrc%2Fserver.js", "/%2e%2e/src/server.js", "/nope.js"]) {
      const res = await wb.call(probe);
      assert.ok([400, 404].includes(res.status), `${probe} -> ${res.status}`);
      assert.equal(res.text.includes("createServer"), false);
    }
  } finally {
    await wb.close();
  }
});

test("plaintext never lands in a temp file while rotating", async () => {
  const wb = await boot();
  try {
    const live = (await wb.call("/api/status")).json.liveRun;
    await wb.post(`/api/runs/${live.id}/resume`);
    for (let i = 0; i < 3; i += 1) await wb.post(`/api/runs/${live.id}/step`);
    const plain = (await wb.post("/api/read", { rowId: 1, column: "audit_ref" })).json.plaintext;
    assert.match(plain, /^audit:\/\/fictional\//);

    // Scan the data dir for any file containing the plaintext.
    const hits = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (fs.statSync(full).size < 8 * 1024 * 1024) {
          const buf = fs.readFileSync(full);
          if (buf.includes(Buffer.from(plain))) hits.push(full);
        }
      }
    };
    walk(wb.dir);
    assert.deepEqual(hits, [], `plaintext found in: ${hits.join(", ")}`);
  } finally {
    await wb.close();
  }
});

test("revocation through HTTP invalidates cached plaintext immediately", async () => {
  const wb = await boot();
  try {
    const first = await wb.post("/api/read", { rowId: 2, column: "audit_ref" });
    assert.equal(first.json.source, "db");
    const cached = await wb.post("/api/read", { rowId: 2, column: "audit_ref" });
    assert.equal(cached.json.source, "cache");

    const revoked = await wb.post("/api/purposes/audit/revoke");
    assert.equal(revoked.status, 200);
    assert.ok(revoked.json.cachePurged >= 1);

    const after = await wb.post("/api/read", { rowId: 2, column: "audit_ref" });
    assert.equal(after.status, 403);
    assert.equal(after.json.error.code, "PURPOSE_REVOKED");
    const write = await wb.post("/api/events", {});
    assert.equal(write.status, 400);
    const rotation = await wb.post("/api/runs", { purpose: "audit", chunkSize: 5 });
    assert.equal(rotation.status, 409);
  } finally {
    await wb.close();
  }
});

test("slug/format validation rejects malformed key ids and endpoints", async () => {
  const wb = await boot();
  try {
    const bad = await wb.call(`/api/keys/not-a-key/readiness`);
    assert.equal(bad.status, 404);
    assert.equal(bad.json.error.code, "NOT_FOUND");
    const ok = await wb.call(`/api/keys/${encodeKeyId(1)}/readiness`);
    assert.equal(ok.status, 200);
    assert.equal(typeof ok.json.ready, "boolean");
    const nope = await wb.call("/api/unknown");
    assert.equal(nope.status, 404);
    const put = await wb.call("/api/status", { method: "PUT" });
    assert.equal(put.status, 404);
  } finally {
    await wb.close();
  }
});

test("HEAD returns headers without a body", async () => {
  const wb = await boot();
  try {
    const res = await fetch(`${wb.base}/`, { method: "HEAD" });
    assert.equal(res.status, 200);
    assert.equal(await res.text(), "");
    assert.match(res.headers.get("content-type"), /text\/html/);
  } finally {
    await wb.close();
  }
});

// src/server.js
// Local HTTP server: JSON API + static UI. Binds to 127.0.0.1 by default.
//
// Safety properties:
//  - API errors are returned as {code, message, details} with no stack traces,
//    no plaintext, and no key material.
//  - Request bodies are size-limited and parsed as JSON only.
//  - Static file serving is confined to public/ (no path traversal).
//  - No inline reflection of request data into HTML error pages.

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ServiceError } from "./service.js";
import { CryptoError } from "./crypto.js";
import { KeyringError } from "./keyring.js";
import { RotationError } from "./rotation.js";
import { LeaseError } from "./leases.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(__dirname, "..", "public");
const MAX_BODY = 256 * 1024;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(body);
}

function sendText(res, status, text, type = "text/plain; charset=utf-8") {
  res.writeHead(status, {
    "content-type": type,
    "content-length": Buffer.byteLength(text),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(text);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let rejected = false;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        if (!rejected) {
          rejected = true;
          chunks.length = 0;
          // Drain the rest so the 413 response can still be written cleanly,
          // but never buffer an unbounded body.
          req.resume();
          reject(new ServiceError("BODY_TOO_LARGE", "request body too large", {}, 413));
        }
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (rejected) return;
      if (chunks.length === 0) return resolve({});
      const raw = Buffer.concat(chunks).toString("utf8");
      try {
        const parsed = JSON.parse(raw);
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          reject(new ServiceError("BAD_JSON", "body must be a JSON object", {}, 400));
          return;
        }
        resolve(parsed);
      } catch {
        reject(new ServiceError("BAD_JSON", "body is not valid JSON", {}, 400));
      }
    });
    req.on("error", (err) => {
      if (!rejected) reject(err);
    });
  });
}

function parseUrl(req) {
  const url = new URL(req.url, "http://127.0.0.1");
  return { pathname: url.pathname, query: url.searchParams };
}

/** Map internal error types to a stable, non-leaky JSON shape. */
function toErrorResponse(err) {
  if (err instanceof ServiceError) {
    return {
      status: err.status || 400,
      body: { error: { code: err.code, message: err.message, details: sanitizeDetails(err) } },
    };
  }
  if (err instanceof RotationError) {
    return {
      status: 409,
      body: {
        error: {
          code: err.code,
          message: err.message,
          details: { rowId: err.rowId ?? null, cause: err.cause ?? null },
        },
      },
    };
  }
  if (err instanceof KeyringError) {
    return {
      status: 409,
      body: { error: { code: err.code, message: err.message, details: { reasons: err.reasons || [] } } },
    };
  }
  if (err instanceof CryptoError) {
    return {
      status: 422,
      body: { error: { code: err.code, message: err.message, details: {} } },
    };
  }
  if (err instanceof LeaseError) {
    return { status: 409, body: { error: { code: err.code, message: err.message, details: {} } } };
  }
  // Unknown error: log server-side type only, never contents.
  console.error("[server] unhandled error type:", err?.constructor?.name || "unknown");
  return {
    status: 500,
    body: { error: { code: "INTERNAL", message: "internal error", details: {} } },
  };
}

function sanitizeDetails(err) {
  const out = {};
  for (const key of ["purpose", "column", "rowId", "keyId", "runId", "reasons", "activeLeases", "cachePurged", "envelopePurpose", "requestedPurpose", "revokedAt"]) {
    if (err[key] !== undefined) out[key] = err[key];
  }
  return out;
}

export function createHandler(service) {
  return async (req, res) => {
    const { pathname, query } = parseUrl(req);
    try {
      if (pathname.startsWith("/api/")) {
        await handleApi(req, res, pathname, query, service);
        return;
      }
      serveStatic(req, res, pathname);
    } catch (err) {
      const { status, body } = toErrorResponse(err);
      if (pathname.startsWith("/api/")) {
        sendJson(res, status, body);
      } else {
        // Generic error page; never echo request data or plaintext.
        sendText(
          res,
          status,
          `<!doctype html><meta charset="utf-8"><title>错误</title>
<body style="font-family:system-ui;padding:2rem;background:#0f1115;color:#e6e8ee">
<h1>请求无法完成</h1><p>错误码：${escapeHtml(body.error.code)}</p>
<p>未写入任何明文临时文件。请返回工作台重试。</p>
</body>`,
          "text/html; charset=utf-8",
        );
      }
    }
  };
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function serveStatic(req, res, pathname) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    sendJson(res, 405, { error: { code: "METHOD_NOT_ALLOWED", message: "method not allowed" } });
    return;
  }
  let rel = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const file = path.resolve(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep) && file !== path.join(PUBLIC_DIR, "index.html")) {
    sendText(res, 404, "Not found");
    return;
  }
  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    sendText(res, 404, "Not found");
    return;
  }
  if (!stat.isFile()) {
    sendText(res, 404, "Not found");
    return;
  }
  const data = fs.readFileSync(file);
  const type = MIME[path.extname(file)] || "application/octet-stream";
  res.writeHead(200, {
    "content-type": type,
    "content-length": data.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy":
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  });
  if (req.method === "HEAD") res.end();
  else res.end(data);
}

async function handleApi(req, res, pathname, query, service) {
  const method = req.method;

  // ---- read ----
  if (method === "GET" && pathname === "/api/status") {
    return sendJson(res, 200, service.status());
  }
  if (method === "GET" && pathname === "/api/manifest") {
    return sendJson(res, 200, service.manifest());
  }
  if (method === "GET" && pathname === "/api/events") {
    const limit = Number(query.get("limit") || 20);
    const offset = Number(query.get("offset") || 0);
    const decrypt = query.get("decrypt") !== "0";
    return sendJson(res, 200, service.listEvents({ limit, offset, decrypt }));
  }
  if (method === "GET" && pathname === "/api/distribution") {
    return sendJson(res, 200, service.keyDistribution());
  }
  if (method === "GET" && pathname === "/api/leases") {
    return sendJson(res, 200, service.status().leases);
  }

  const m = pathname.match(/^\/api\/keys\/([0-9a-f]{16})(?:\/(readiness))?$/);
  if (m && method === "GET") {
    if (m[2] === "readiness") {
      return sendJson(res, 200, service.keyDestroyReadiness(m[1]));
    }
    const keys = service.status().keys.filter((k) => k.key_id === m[1]);
    if (!keys.length) throw new ServiceError("UNKNOWN_KEY", "unknown key", {}, 404);
    return sendJson(res, 200, keys[0]);
  }

  const runMatch = pathname.match(/^\/api\/runs\/([A-Za-z0-9_-]+)$/);
  if (runMatch) {
    if (method === "GET") return sendJson(res, 200, service.getRunDetail(runMatch[1]));
    // Same shape as a known run path but wrong method: report the run as missing
    // only when it truly is, otherwise it is a method error.
    if (service.runExists(runMatch[1])) {
      throw new ServiceError("METHOD_NOT_ALLOWED", "method not allowed", {}, 405);
    }
    throw new ServiceError("UNKNOWN_RUN", `unknown run ${runMatch[1]}`, {}, 404);
  }

  if (method === "POST") {
    const body = await readBody(req);

    if (pathname === "/api/events") {
      return sendJson(res, 201, service.createEvent(body));
    }
    if (pathname === "/api/read") {
      return sendJson(
        res,
        200,
        service.readValue({
          rowId: Number(body.rowId),
          column: String(body.column || ""),
          useCache: body.useCache !== false,
          leaseTtlMs: body.leaseTtlMs ? Number(body.leaseTtlMs) : undefined,
        }),
      );
    }
    const rewrite = pathname.match(/^\/api\/events\/(\d+)\/rewrite$/);
    if (rewrite) {
      return sendJson(res, 200, service.rewriteEvent(Number(rewrite[1]), String(body.column || "")));
    }
    if (pathname === "/api/keys") {
      return sendJson(
        res,
        201,
        service.createKeyForPurpose({
          purpose: String(body.purpose || ""),
          label: body.label ? String(body.label).slice(0, 80) : "",
          activate: Boolean(body.activate),
        }),
      );
    }
    const promote = pathname.match(/^\/api\/keys\/([0-9a-f]{16})\/promote$/);
    if (promote) {
      return sendJson(
        res,
        200,
        service.promote({
          keyId: promote[1],
          graceSeconds: body.graceSeconds === undefined ? undefined : Number(body.graceSeconds),
        }),
      );
    }
    const destroy = pathname.match(/^\/api\/keys\/([0-9a-f]{16})\/destroy$/);
    if (destroy) {
      return sendJson(
        res,
        200,
        service.destroy({
          keyId: destroy[1],
          graceSeconds: body.graceSeconds === undefined ? undefined : Number(body.graceSeconds),
        }),
      );
    }
    const revoke = pathname.match(/^\/api\/purposes\/([a-z]+)\/(revoke|restore)$/);
    if (revoke) {
      const handler = revoke[2] === "revoke" ? service.revoke.bind(service) : service.restore.bind(service);
      return sendJson(res, 200, handler(revoke[1]));
    }
    if (pathname === "/api/leases") {
      // Hold a manual lease so the UI can demonstrate "destroy is refused while
      // an old reader is still using the key".
      const { acquireLease } = await import("./leases.js");
      const purpose = String(body.purpose || "");
      const keyId = String(body.keyId || "");
      const ttlMs = Math.max(1000, Math.min(Number(body.ttlMs) || 60_000, 30 * 60 * 1000));
      const column = { analytics: "session_label", pii: "customer_email", audit: "audit_ref" }[purpose];
      if (!column) throw new ServiceError("BAD_PURPOSE", "unknown purpose", {}, 400);
      const lease = acquireLease(service.db, {
        kind: "manual",
        holder: service.instanceId,
        keyId,
        purpose,
        column,
        ttlMs,
      });
      return sendJson(res, 201, lease);
    }
    if (pathname === "/api/runs") {
      return sendJson(
        res,
        201,
        service.startRotation({
          purpose: String(body.purpose || ""),
          chunkSize: body.chunkSize,
          strategy: body.strategy ? String(body.strategy) : undefined,
        }),
      );
    }
    const step = pathname.match(/^\/api\/runs\/([A-Za-z0-9_-]+)\/step$/);
    if (step) {
      return sendJson(res, 200, {
        step: service.rotateStep(step[1], { chunkSize: body.chunkSize }),
        detail: service.getRunDetail(step[1]),
      });
    }
    const runAll = pathname.match(/^\/api\/runs\/([A-Za-z0-9_-]+)\/run-all$/);
    if (runAll) {
      return sendJson(res, 200, service.runAll(runAll[1]));
    }
    const pause = pathname.match(/^\/api\/runs\/([A-Za-z0-9_-]+)\/pause$/);
    if (pause) return sendJson(res, 200, { run: service.pause(pause[1]) });
    const resume = pathname.match(/^\/api\/runs\/([A-Za-z0-9_-]+)\/resume$/);
    if (resume) return sendJson(res, 200, { run: service.resume(resume[1]) });
    const rollback = pathname.match(/^\/api\/runs\/([A-Za-z0-9_-]+)\/rollback$/);
    if (rollback) return sendJson(res, 200, service.rollback(rollback[1]));
    const dropBackup = pathname.match(/^\/api\/runs\/([A-Za-z0-9_-]+)\/drop-backup$/);
    if (dropBackup) return sendJson(res, 200, service.dropBackup(dropBackup[1]));
    const abandon = pathname.match(/^\/api\/runs\/([A-Za-z0-9_-]+)\/abandon$/);
    if (abandon) return sendJson(res, 200, { run: service.abandon(abandon[1], String(body.note || "")) });
    if (pathname === "/api/cache/purge") {
      service.cache.clear();
      return sendJson(res, 200, { purged: true, cache: service.cache.stats() });
    }
    if (pathname === "/api/recover") {
      return sendJson(res, 200, service.recover());
    }
    if (pathname === "/api/demo/write-burst") {
      const count = Math.max(1, Math.min(Number(body.count) || 5, 50));
      const created = [];
      for (let i = 0; i < count; i += 1) created.push(service.createEvent({}));
      return sendJson(res, 201, { created: created.length, ids: created.map((r) => r.id) });
    }
  }

  if (method === "DELETE") {
    const lease = pathname.match(/^\/api\/leases\/([0-9a-f]{16})$/);
    if (lease) {
      const { releaseLease } = await import("./leases.js");
      return sendJson(res, 200, { released: releaseLease(service.db, lease[1]) });
    }
  }

  throw new ServiceError("NOT_FOUND", "no such endpoint", {}, 404);
}

export function createServer(service) {
  const server = http.createServer(createHandler(service));
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  return server;
}

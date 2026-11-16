// test/ui-smoke.test.js
// Executes public/app.js against a minimal DOM shim and the real HTTP API.
// This is not a rendering test; it catches controller-level crashes (missing
// elements, bad payload assumptions) that a browserless environment would
// otherwise hide. No third-party dependencies.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveConfig } from "../src/config.js";
import { openDb, ensureSchema } from "../src/db.js";
import { WorkbenchService } from "../src/service.js";
import { createServer } from "../src/server.js";

class FakeClassList {
  constructor(node) { this.node = node; this.set = new Set(); }
  add(...names) { for (const n of names) this.set.add(n); this.sync(); }
  remove(...names) { for (const n of names) this.set.delete(n); this.sync(); }
  contains(name) { return this.set.has(name); }
  sync() { this.node._className = [...this.set].join(" "); }
}

class FakeElement {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.listeners = new Map();
    this._className = "";
    this.textContent = "";
    this.hidden = false;
    this.disabled = false;
    this.type = "";
    this.style = {};
    this.dataset = {};
    this.classList = new FakeClassList(this);
    this._id = "";
  }
  get className() { return this._className; }
  set className(v) {
    this._className = v;
    this.classList.set = new Set(String(v).split(/\s+/).filter(Boolean));
  }
  get id() { return this._id; }
  set id(v) { this._id = v; }
  get childElementCount() { return this.children.length; }
  append(...nodes) {
    for (const n of nodes) {
      if (n == null) continue;
      this.children.push(n);
      if (n && n._id) {} // no-op
    }
  }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  async click() {
    for (const fn of this.listeners.get("click") || []) await fn({ preventDefault() {} });
  }
  querySelector(sel) {
    if (sel === "tbody") {
      if (!this._tbody) {
        this._tbody = new FakeElement("tbody");
        this._tbody.parent = this;
      }
      return this._tbody;
    }
    return null;
  }
  setAttribute() {}
  focus() {}
  get textContentAll() {
    return [this.textContent, ...this.children.map((c) => (c instanceof FakeElement ? c.textContentAll : String(c)))].join(" ");
  }
}

function installDom() {
  const ids = [...fs.readFileSync(path.join(process.cwd(), "public", "index.html"), "utf8").matchAll(/id="([^"]+)"/g)].map((m) => m[1]);
  const nodes = new Map();
  for (const id of ids) {
    const el = new FakeElement("div");
    el.id = id;
    nodes.set(id, el);
  }
  // Pre-create the table body so querySelector("tbody") works after render.
  const table = nodes.get("eventsTable");
  table.querySelector("tbody");

  const segButtons = ["in_place_chunked", "shadow_copy"].map((strategy) => {
    const b = new FakeElement("button");
    b.dataset.strategy = strategy;
    if (strategy === "in_place_chunked") b.className = "seg-btn is-on";
    else b.className = "seg-btn";
    return b;
  });

  const document = {
    getElementById: (id) => nodes.get(id) ?? null,
    createElement: (tag) => new FakeElement(tag),
    querySelectorAll: (sel) => (sel === ".seg-btn" ? segButtons : []),
  };
  const toasts = [];
  const alerts = [];
  const confirm = () => true;
  const timers = [];
  const setIntervalShim = (fn, ms) => { const t = { fn, ms }; timers.push(t); return t; };
  const clearIntervalShim = (t) => { const i = timers.indexOf(t); if (i >= 0) timers.splice(i, 1); };
  return { document, nodes, segButtons, toasts, alerts, confirm, timers, setIntervalShim, clearIntervalShim };
}

test("UI controller renders and drives the API without crashing", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rk-ui-"));
  const config = resolveConfig({ dataDir: dir, graceSeconds: 0 });
  const db = openDb(config.dbPath);
  ensureSchema(db);
  const service = new WorkbenchService({ db, config });
  service.bootstrap({ rowCount: 60 });
  const server = createServer(service);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  const dom = installDom();
  const originalFetch = globalThis.fetch;
  globalThis.document = dom.document;
  globalThis.fetch = (url, opts) => originalFetch(String(url).startsWith("http") ? url : base + url, opts);
  globalThis.confirm = dom.confirm;
  globalThis.setInterval = dom.setIntervalShim;
  globalThis.clearInterval = dom.clearIntervalShim;
  const errors = [];
  globalThis.addEventListener = () => {};
  const onUnhandled = (e) => errors.push(e);
  process.on("unhandledRejection", onUnhandled);

  try {
    await import("../public/app.js?smoke=" + Date.now());
    // refresh() is fire-and-forget; wait until the last stage (events) renders.
    const tbody = dom.nodes.get("eventsTable").querySelector("tbody");
    for (let i = 0; i < 100 && !tbody.children.length; i += 1) {
      await new Promise((r) => setTimeout(r, 50));
    }
    const keyList = dom.nodes.get("keyList");
    assert.ok(keyList.children.length >= 3, "keys rendered");
    assert.match(dom.nodes.get("statGrid").textContentAll, /总行数/);
    assert.match(dom.nodes.get("manifestView").textContent, /AES-256-GCM/);
    assert.match(dom.nodes.get("eventsTable").querySelector("tbody").textContentAll, /example\.test/);

    // Resume + run the seeded rotation through UI buttons.
    const runPanel = dom.nodes.get("runPanel");
    const findButton = (label) => runPanel.children
      .flatMap((c) => (c instanceof FakeElement ? c.children : []))
      .find((c) => c && c.textContent === label);
    const resume = findButton("恢复");
    assert.ok(resume, `resume button exists; panel=${runPanel.textContentAll.slice(0, 200)}`);
    await resume.click();
    await new Promise((r) => setTimeout(r, 300));
    const runAll = findButton("跑到结束");
    assert.ok(runAll, "run-all button exists");
    await runAll.click();
    await new Promise((r) => setTimeout(r, 600));

    const status = await (await originalFetch(`${base}/api/status`)).json();
    assert.equal(status.liveRun, null, "run completed and cleared");

    // Read a cell through the UI.
    dom.nodes.get("readRow").value = "1";
    dom.nodes.get("readCol").value = "customer_email";
    dom.nodes.get("readCache").checked = true;
    await dom.nodes.get("doRead").click();
    await new Promise((r) => setTimeout(r, 200));
    assert.match(dom.nodes.get("readResult").textContentAll, /读取成功/);

    // Append a record through the UI.
    await dom.nodes.get("newWrite").click();
    await new Promise((r) => setTimeout(r, 250));
    assert.match(dom.nodes.get("writeResult").textContentAll + dom.nodes.get("toast").textContent, /完成|追加/);

    // Revoke a purpose and read again: must show the error, not a value.
    dom.nodes.get("revPurpose").value = "pii";
    await dom.nodes.get("revoke").click();
    await new Promise((r) => setTimeout(r, 300));
    dom.nodes.get("readRow").value = "1";
    dom.nodes.get("readCol").value = "customer_email";
    await dom.nodes.get("doRead").click();
    await new Promise((r) => setTimeout(r, 200));
    assert.match(dom.nodes.get("readResult").textContentAll, /PURPOSE_REVOKED|撤销/);

    assert.deepEqual(errors.map((e) => e?.message), [], "no unhandled rejections");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    globalThis.fetch = originalFetch;
    delete globalThis.document;
    delete globalThis.confirm;
    delete globalThis.setInterval;
    delete globalThis.clearInterval;
    await new Promise((r) => server.close(r));
    db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

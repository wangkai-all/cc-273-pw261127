// public/app.js
// Minimal UI controller. No framework, no build step, no external requests.
// The browser never receives key material or plaintext of purpose-revoked data.

const state = {
  status: null,
  manifest: null,
  page: 0,
  pageSize: 20,
  strategy: "in_place_chunked",
  poll: null,
};

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text != null) node.textContent = text;
  return node;
};

async function api(path, { method = "GET", body = null } = {}) {
  const opts = { method, headers: { accept: "application/json" } };
  if (body !== null) {
    opts.headers["content-type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const err = new Error(data?.error?.message || `HTTP ${res.status}`);
    err.code = data?.error?.code || "HTTP_ERROR";
    err.details = data?.error?.details || {};
    err.status = res.status;
    throw err;
  }
  return data;
}

let toastTimer = null;
function toast(message, kind = "") {
  const node = $("toast");
  node.textContent = message;
  node.className = `toast ${kind}`;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.hidden = true;
  }, 5200);
}

function banner(message, kind = "") {
  const node = $("banner");
  if (!message) {
    node.hidden = true;
    return;
  }
  node.textContent = message;
  node.className = `banner ${kind}`;
  node.hidden = false;
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("zh-CN", { hour12: false });
}

function shortId(id) {
  return id ? String(id) : "—";
}

function badge(status) {
  const labels = {
    active: "活动",
    retiring: "退休中",
    staged: "已暂存",
    destroyed: "已销毁",
    running: "运行中",
    paused: "已暂停",
    interrupted: "已中断",
    verifying: "校验中",
    rolling_back: "回滚中",
    rollback_interrupted: "回滚中断",
    completed: "已完成",
    failed: "失败",
    rolled_back: "已回滚",
    abandoned: "已放弃",
  };
  const b = el("span", `badge ${status}`, labels[status] || status);
  return b;
}

function reasonText(reason) {
  const map = {
    key_is_active: "这是活动钥",
    grace_period_not_elapsed: "静默期未结束",
    no_retirement_timestamp: "缺少退休时间",
    staged_key_never_destroy_until_promoted_or_abandoned: "暂存钥不可销毁",
    already_destroyed: "已销毁",
    readiness_unavailable: "无法评估",
  };
  if (reason.startsWith("live_rows_still_under_key")) return `活跃表仍有旧密文 ${reason.split(":")[1]} 行`;
  if (reason.startsWith("backup_rows_still_under_key")) return `备份表仍有旧密文 ${reason.split(":")[1]} 行`;
  if (reason.startsWith("shadow_rows_still_under_key")) return `影子表仍有旧密文 ${reason.split(":")[1]} 行`;
  if (reason.startsWith("rows_still_under_key")) return `仍有旧密文 ${reason.split(":")[1]} 行`;
  if (reason.startsWith("active_leases")) return `有 ${reason.split(":")[1]} 个活动租约`;
  if (reason.startsWith("active_purpose_leases")) return `该用途有 ${reason.split(":")[1]} 个活动租约`;
  if (reason.startsWith("live_runs")) return `有 ${reason.split(":")[1]} 个未终结任务`;
  return map[reason] || reason;
}

// ---------- render ----------

function renderOverview(s) {
  const grid = $("statGrid");
  grid.replaceChildren();
  const stats = [
    { k: "总行数", v: s.totalRows },
    { k: "两代并存列", v: countMixedColumns(s), small: "列" },
    { k: "活动租约", v: s.leases.activeCount },
    { k: "缓存条数", v: s.cache.entries, small: `命中 ${s.cache.hits}` },
  ];
  for (const st of stats) {
    const box = el("div", "stat");
    box.append(el("div", "k", st.k));
    const v = el("div", "v", String(st.v));
    if (st.small) v.append(el("small", null, ` ${st.small}`));
    box.append(v);
    grid.append(box);
  }

  const plist = $("purposeList");
  plist.replaceChildren();
  for (const p of s.purposes) {
    const row = el("div", "purpose-row");
    const left = el("div");
    left.append(el("div", "p", p.purpose));
    left.append(el("div", "meta", `${p.column} · 活动钥 ${p.activeKeyId || "无"}`));
    row.append(left);
    if (p.revokedAt) row.append(el("span", "badge destroyed", "已撤销"));
    else row.append(badge("active"));
    plist.append(row);
  }
}

function countMixedColumns(s) {
  let n = 0;
  for (const col of Object.keys(s.distribution || {})) {
    if (Object.keys(s.distribution[col]).filter((k) => k !== "corrupt").length > 1) n += 1;
  }
  return n;
}

function renderKeys(s) {
  const list = $("keyList");
  list.replaceChildren();
  for (const k of s.keys) {
    const box = el("div", "key");
    const line1 = el("div", "line1");
    line1.append(el("span", "kid", k.keyId));
    line1.append(badge(k.status));
    box.append(line1);
    const detail = el("div", "lbl", `${k.purpose} · ${k.label} · 指纹 ${k.fingerprint}`);
    box.append(detail);

    if (k.status !== "destroyed" && k.readiness) {
      if (k.readiness.ready) {
        const why = el("div", "why");
        why.style.color = "var(--good)";
        why.append(el("span", null, "全部退出条件已满足，可销毁"));
        box.append(why);
      } else if (k.readiness.reasons.length) {
        const why = el("div", "why");
        for (const r of k.readiness.reasons.slice(0, 4)) why.append(el("span", "chip", reasonText(r)));
        box.append(why);
      }
    }

    const actions = el("div", "actions");
    if (k.status === "staged") {
      const promote = el("button", "btn tiny", "启用");
      promote.type = "button";
      promote.addEventListener("click", () => act(`启用 ${k.keyId}`, () => api(`/api/keys/${k.keyId}/promote`, { method: "POST", body: {} })));
      actions.append(promote);
    }
    if (k.status === "retiring" || k.status === "staged") {
      const destroy = el("button", "btn tiny danger", k.readiness?.ready ? "销毁" : "销毁（不可用）");
      destroy.type = "button";
      destroy.disabled = !k.readiness?.ready;
      destroy.addEventListener("click", () => {
        if (!confirm(`确定销毁密钥 ${k.keyId}？销毁后任何仍使用它的密文都将无法解密。`)) return;
        act(`销毁 ${k.keyId}`, () => api(`/api/keys/${k.keyId}/destroy`, { method: "POST", body: {} }));
      });
      actions.append(destroy);
    }
    if (actions.childElementCount) box.append(actions);
    list.append(box);
  }
  if (!s.keys.length) list.append(el("div", "empty", "尚未创建密钥"));
}

function renderRun(s) {
  const panel = $("runPanel");
  panel.replaceChildren();
  const run = s.liveRun;
  if (!run) {
    panel.append(el("div", "empty", "当前没有未终结的轮换。选择用途后点击开始。"));
    const recent = s.recentRuns.filter((r) => ["completed", "rolled_back", "abandoned"].includes(r.status));
    if (recent.length) {
      const h = el("h3", null, "最近结束");
      panel.append(h);
      const mini = el("div", "mini-list");
      for (const r of recent.slice(0, 3)) {
        const row = el("div", "mini");
        const l = el("div", "l");
        l.append(el("div", "t", `${r.purpose} · ${r.id}`));
        l.append(el("div", "s", `${fmtTime(r.finishedAt)} · ${r.processedRows}/${r.totalRows} 行`));
        row.append(l);
        row.append(badge(r.status));
        mini.append(row);
      }
      panel.append(mini);
    }
    return;
  }

  const head = el("div", "run-head");
  head.append(badge(run.status));
  head.append(el("span", "mono dim", run.id));
  const pct = run.progress || 0;
  head.append(el("span", "dim", `${run.processed_rows}/${run.total_rows} 行 · ${pct}%`));
  panel.append(head);

  if (run.error) {
    const e = el("div", "result");
    e.append(el("div", "err", `错误：${run.error}`));
    panel.append(e);
  }

  const prog = el("div", "progress");
  const bar = el("i");
  bar.style.width = `${pct}%`;
  prog.append(bar);
  panel.append(prog);

  const g = el("div", "run-grid");
  const cells = [
    ["已迁移", run.migrated_rows ?? 0],
    ["跳过", run.skipped_rows ?? 0],
    ["校验", `${run.verified_rows ?? 0}`],
    ["校验错误", run.verification_errors ?? 0],
  ];
  for (const [k, v] of cells) {
    const box = el("div", "stat");
    box.append(el("div", "k", k));
    box.append(el("div", "v", String(v)));
    g.append(box);
  }
  panel.append(g);

  const dist = el("div", "dist");
  for (const [kid, n] of Object.entries(run.distribution || {})) {
    const cls = kid === run.to_key_id ? "cur" : kid === run.from_key_id ? "old" : "";
    const d = el("div", `d ${cls}`, `${kid === run.to_key_id ? "新" : kid === run.from_key_id ? "旧" : "?"} ${kid.slice(-6)} × ${n}`);
    dist.append(d);
  }
  panel.append(dist);

  const actions = el("div", "form-row tight");
  const isActive = ["running", "verifying"].includes(run.status);
  const stepBtn = el("button", "btn primary", run.status === "verifying" ? "校验一块" : "迁移一块");
  stepBtn.type = "button";
  stepBtn.disabled = !isActive;
  stepBtn.addEventListener("click", () => act("推进一块", () => api(`/api/runs/${run.id}/step`, { method: "POST", body: {} })));
  actions.append(stepBtn);

  const allBtn = el("button", "btn", "跑到结束");
  allBtn.type = "button";
  allBtn.disabled = !isActive;
  allBtn.addEventListener("click", () => act("跑到结束", () => api(`/api/runs/${run.id}/run-all`, { method: "POST", body: {} })));
  actions.append(allBtn);

  if (run.status === "running") {
    const p = el("button", "btn ghost", "暂停");
    p.type = "button";
    p.addEventListener("click", () => act("暂停", () => api(`/api/runs/${run.id}/pause`, { method: "POST", body: {} })));
    actions.append(p);
  }
  if (["paused", "interrupted", "failed"].includes(run.status)) {
    const r = el("button", "btn", run.status === "failed" ? "修复后继续" : "恢复");
    r.type = "button";
    r.addEventListener("click", () => act("恢复", () => api(`/api/runs/${run.id}/resume`, { method: "POST", body: {} })));
    actions.append(r);
  }
  if (["failed", "interrupted", "paused", "rollback_interrupted"].includes(run.status)) {
    const rb = el("button", "btn danger", "从备份回滚");
    rb.type = "button";
    rb.addEventListener("click", () => {
      if (!confirm("从备份回滚已迁移的行？并发改写过的行会被记为冲突并保留现值。")) return;
      act("回滚", () => api(`/api/runs/${run.id}/rollback`, { method: "POST", body: {} }));
    });
    actions.append(rb);
  }
  if (["completed", "rolled_back"].includes(run.status) && run.backup_table) {
    const drop = el("button", "btn danger", "删除备份表");
    drop.type = "button";
    drop.addEventListener("click", () => {
      if (!confirm("删除备份后无法再回滚。旧钥也不会自动销毁。")) return;
      act("删除备份", () => api(`/api/runs/${run.id}/drop-backup`, { method: "POST", body: {} }));
    });
    actions.append(drop);
  }
  if (run.status === "failed") {
    const ab = el("button", "btn ghost", "放弃任务（保留备份）");
    ab.type = "button";
    ab.addEventListener("click", () => act("放弃任务", () => api(`/api/runs/${run.id}/abandon`, { method: "POST", body: {} })));
    actions.append(ab);
  }
  panel.append(actions);

  if (run.backupRows != null) {
    panel.append(el("p", "hint", `备份表现有 ${run.backupRows} 行；回滚已恢复 ${run.rollback_restored ?? 0} 行，冲突 ${run.rollback_conflicts ?? 0} 行。`));
  }

  const logBox = el("div", "log");
  for (const line of run.log || []) {
    const row = el("div", `ln ${line.level}`);
    row.append(el("span", "at", new Date(line.at).toLocaleTimeString("zh-CN", { hour12: false })));
    row.append(el("span", null, line.message));
    logBox.append(row);
  }
  panel.append(logBox);
}

function renderLeases(s) {
  const list = $("leaseList");
  list.replaceChildren();
  if (!s.leases.leases.length) {
    list.append(el("div", "empty", "没有活动租约"));
    return;
  }
  for (const lease of s.leases.leases) {
    const row = el("div", "mini");
    const l = el("div", "l");
    l.append(el("div", "t", `${lease.purpose} · ${lease.key_id}`));
    l.append(el("div", "s", `${lease.kind} · 到期 ${fmtTime(lease.expires_at)}`));
    row.append(l);
    const rel = el("button", "btn tiny ghost", "释放");
    rel.type = "button";
    rel.addEventListener("click", () => act("释放租约", () => api(`/api/leases/${lease.id}`, { method: "DELETE" })));
    row.append(rel);
    list.append(row);
  }
}

function renderCache(s) {
  const box = $("cacheInfo");
  box.replaceChildren();
  const c = s.cache;
  const row = el("div", "mini");
  const l = el("div", "l");
  l.append(el("div", "t", `${c.entries}/${c.maxEntries} 条`));
  l.append(el("div", "s", `命中 ${c.hits} · 未命中 ${c.misses} · 驱逐 ${c.evictions}`));
  row.append(l);
  box.append(row);
  const parts = Object.entries(c.byPurpose || {});
  if (parts.length) {
    const row2 = el("div", "mini");
    const l2 = el("div", "l");
    l2.append(el("div", "t", parts.map(([p, n]) => `${p}:${n}`).join("  ")));
    l2.append(el("div", "s", "仅进程内存，不落盘"));
    row2.append(l2);
    box.append(row2);
  }
}

function renderManifest(m) {
  $("manifestView").textContent = JSON.stringify(
    {
      generatedAt: m.generatedAt,
      cipher: m.cipher,
      keys: m.keys.map((k) => ({ keyId: k.keyId, purpose: k.purpose, status: k.status, fingerprint: k.fingerprint })),
      purposes: m.purposes,
      distribution: m.distribution,
      warnings: m.warnings,
    },
    null,
    2,
  );
}

function renderEvents(data) {
  const tbody = $("eventsTable").querySelector("tbody");
  tbody.replaceChildren();
  for (const row of data.items) {
    const tr = document.createElement("tr");
    const cells = [
      ["id", row.id, null],
      ["time", fmtTime(row.occurred_at), null],
      ["region", row.region, null],
      ["plan", row.plan, null],
      ["money", (row.revenue_minor / 100).toFixed(2), null],
    ];
    for (const [, value] of cells) {
      const td = document.createElement("td");
      td.textContent = value;
      tr.append(td);
    }
    for (const col of ["customer_email", "session_label", "audit_ref"]) {
      const td = el("td", "cell");
      const err = row.errors?.[col];
      if (err) {
        td.classList.add("err");
        td.append(el("span", "val", `不可读 (${err})`));
      } else {
        td.append(el("span", "val", row.values[col] == null ? "—" : row.values[col]));
      }
      if (row.encrypted[col]) td.append(el("span", "kid", row.encrypted[col].slice(-6)));
      tr.append(td);
    }
    tbody.append(tr);
  }
  const start = data.offset + 1;
  const end = Math.min(data.offset + data.limit, data.total);
  $("pageLabel").textContent = `${data.total ? start : 0}–${end} / ${data.total}`;
  $("prevPage").disabled = data.offset <= 0;
  $("nextPage").disabled = end >= data.total;
}

function renderBanner(s) {
  if (s.keys.some((k) => k.status === "retiring") && s.leases.activeCount > 0) {
    banner("有旧钥处于退休期且仍有活动租约：销毁会被拒绝，这是预期行为。", "");
  } else if (s.purposes.some((p) => p.revokedAt)) {
    const revoked = s.purposes.filter((p) => p.revokedAt).map((p) => p.purpose).join(", ");
    banner(`用途 ${revoked} 已撤销：读取、写入与轮换均被拒绝，密文仍在盘中但不可解。`, "bad");
  } else if (s.liveRun && s.liveRun.status === "interrupted") {
    banner("检测到上一次进程遗留的轮换任务，已标记为中断；可从游标继续。", "");
  } else {
    banner("");
  }
}

// ---------- actions ----------

async function act(label, fn, { quiet = false } = {}) {
  try {
    const result = await fn();
    if (!quiet) toast(`${label}：完成`, "good");
    await refresh();
    return result;
  } catch (err) {
    const reasons = Array.isArray(err.details?.reasons) && err.details.reasons.length
      ? `（${err.details.reasons.map(reasonText).join("；")}）`
      : "";
    toast(`${label}失败 [${err.code}] ${err.message}${reasons}`, "bad");
    await refresh();
    throw err;
  }
}

async function refresh() {
  try {
    const [status, manifest] = await Promise.all([api("/api/status"), api("/api/manifest")]);
    state.status = status;
    state.manifest = manifest;
    $("inst").textContent = `${status.app.instanceId.split(":")[0]} · pid ${status.app.processId}`;
    renderOverview(status);
    renderKeys(status);
    renderRun(status);
    renderLeases(status);
    renderCache(status);
    renderManifest(manifest);
    renderBanner(status);
    await loadEvents();
    managePoll(status);
  } catch (err) {
    banner(`无法获取状态 [${err.code}] ${err.message}`, "bad");
  }
}

async function loadEvents() {
  try {
    const data = await api(`/api/events?limit=${state.pageSize}&offset=${state.page * state.pageSize}`);
    renderEvents(data);
  } catch (err) {
    toast(`加载数据失败 [${err.code}] ${err.message}`, "bad");
  }
}

function managePoll(s) {
  const live = s.liveRun && ["running", "verifying"].includes(s.liveRun.status);
  if (live && !state.poll) {
    state.poll = setInterval(refresh, 1500);
  } else if (!live && state.poll) {
    clearInterval(state.poll);
    state.poll = null;
  }
}

function bind() {
  $("refresh").addEventListener("click", () => refresh());

  document.querySelectorAll(".seg-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".seg-btn").forEach((b) => b.classList.remove("is-on"));
      btn.classList.add("is-on");
      state.strategy = btn.dataset.strategy;
      const note = $("strategyNote");
      if (state.strategy === "shadow_copy") {
        note.textContent =
          "影子副本：新建整表副本并双写，校验后原子切换表名，再删除旧表。换半时停进程只丢副本，不污染原表；代价是需要约 1 倍表空间、双写或写屏障，以及对账窗口。本工作台未实现该策略，请在文档中比较后选择原地逐块。";
        $("startRot").disabled = true;
      } else {
        note.textContent =
          "原地逐块：先把写入切到新钥，再按 id 游标逐块重加密旧行，每块一个事务。中断后从游标继续；备份表保留迁移前镜像用于回滚。轮换期间读写持续可用。";
        $("startRot").disabled = false;
      }
    });
  });
  $("strategyNote").textContent =
    "原地逐块：先把写入切到新钥，再按 id 游标逐块重加密旧行，每块一个事务。中断后从游标继续；备份表保留迁移前镜像用于回滚。轮换期间读写持续可用。";

  $("startRot").addEventListener("click", () => {
    const purpose = $("rotPurpose").value;
    const chunkSize = Number($("rotChunk").value) || 20;
    const live = state.status?.liveRun;
    if (live && ["running", "verifying"].includes(live.status)) {
      act("跑到结束", () => api(`/api/runs/${live.id}/run-all`, { method: "POST", body: {} }));
      return;
    }
    if (live && ["paused", "interrupted"].includes(live.status)) {
      act("恢复并推进", async () => {
        await api(`/api/runs/${live.id}/resume`, { method: "POST", body: {} });
        return api(`/api/runs/${live.id}/run-all`, { method: "POST", body: {} });
      });
      return;
    }
    act("开始轮换", () => api("/api/runs", { method: "POST", body: { purpose, chunkSize } }));
  });

  $("doRead").addEventListener("click", async () => {
    const box = $("readResult");
    box.replaceChildren();
    try {
      const r = await api("/api/read", {
        method: "POST",
        body: {
          rowId: Number($("readRow").value),
          column: $("readCol").value,
          useCache: $("readCache").checked,
        },
      });
      const ok = el("div", "ok", `读取成功 · 来源 ${r.source}`);
      box.append(ok);
      const kv = el("div", "kv");
      for (const [k, v] of [
        ["行", r.rowId],
        ["列", r.column],
        ["用途", r.purpose],
        ["钥 id", r.keyId || "—"],
      ]) {
        kv.append(el("span", "k", k), el("span", "mono", String(v)));
      }
      box.append(kv);
      box.append(el("div", "pt", r.plaintext == null ? "（空值）" : r.plaintext));
    } catch (err) {
      box.append(el("div", "err", `读取失败 [${err.code}] ${err.message}`));
    }
  });

  $("newWrite").addEventListener("click", () => act("追加记录", () => api("/api/events", { method: "POST", body: {} })));
  $("burstWrite").addEventListener("click", () => act("追加 5 条", () => api("/api/demo/write-burst", { method: "POST", body: { count: 5 } })));
  $("doRewrite").addEventListener("click", async () => {
    const box = $("writeResult");
    box.replaceChildren();
    try {
      const r = await api(`/api/events/${Number($("rewriteRow").value)}/rewrite`, {
        method: "POST",
        body: { column: $("rewriteCol").value },
      });
      box.append(el("div", "ok", "已改用活动钥"));
      const kv = el("div", "kv");
      kv.append(el("span", "k", "钥 id"), el("span", "mono", `${r.fromKeyId} → ${r.toKeyId}`));
      box.append(kv);
      await refresh();
    } catch (err) {
      box.append(el("div", "err", `改写失败 [${err.code}] ${err.message}`));
    }
  });

  $("prevPage").addEventListener("click", () => {
    state.page = Math.max(0, state.page - 1);
    loadEvents();
  });
  $("nextPage").addEventListener("click", () => {
    state.page += 1;
    loadEvents();
  });

  $("addLease").addEventListener("click", () => {
    const purpose = $("leasePurpose").value;
    const manual = $("leaseKey").value.trim();
    const keyId =
      manual ||
      state.status?.keys?.find((k) => k.purpose === purpose && k.status === "retiring")?.keyId ||
      state.status?.purposes?.find((p) => p.purpose === purpose)?.activeKeyId;
    if (!keyId) {
      toast("该用途没有可用钥", "bad");
      return;
    }
    act("占用租约", () =>
      api("/api/leases", {
        method: "POST",
        body: { purpose, keyId, ttlMs: (Number($("leaseTtl").value) || 120) * 1000 },
      }),
    );
  });

  $("revoke").addEventListener("click", () => {
    const purpose = $("revPurpose").value;
    if (!confirm(`撤销用途 ${purpose}？该用途的读取与新写入会立即被拒绝，缓存会被清空。`)) return;
    act(`撤销 ${purpose}`, () => api(`/api/purposes/${purpose}/revoke`, { method: "POST", body: {} }));
  });
  $("restore").addEventListener("click", () => {
    const purpose = $("revPurpose").value;
    act(`恢复 ${purpose}`, () => api(`/api/purposes/${purpose}/restore`, { method: "POST", body: {} }));
  });
  $("purgeCache").addEventListener("click", () => act("清空缓存", () => api("/api/cache/purge", { method: "POST", body: {} })));
}

bind();
refresh();

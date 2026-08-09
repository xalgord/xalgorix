import http from "node:http";
import { WebSocketServer } from "ws";

// ---------------------------------------------------------------------------
// Mock backend for the SPA dev environment.
//
// Shapes here mirror the Go server in internal/web/server.go and the TS types
// in webui/src/types/api.ts. State is held in-memory and mutated by the
// SPA's actions (Stop all, Restart, Delete, Save settings, Resume queue, etc.)
// so the UI feels real end-to-end — without those mutations the dashboard
// looked broken because every action would optimistically succeed and then
// the next poll would revert to the seed state.
// ---------------------------------------------------------------------------

const send = (res, body, status = 200, headers = {}) => {
  res.writeHead(status, {
    "content-type": "application/json",
    "access-control-allow-origin": "*",
    ...headers,
  });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
};
const ok = (res, body = { status: "ok" }) => send(res, body);

const nowIso = () => new Date().toISOString();

let state = {
  instances: [
    {
      id: "inst_01",
      name: "Acme Corp pentest",
      targets: "acme.com",
      parent_target: "acme.com",
      status: "running",
      started_at: nowIso(),
      iterations: 42,
      tool_calls: 188,
      vuln_count: 7,
      total_tokens: 124_000,
      scan_mode: "deep",
      instruction: "Standard recon + active probing",
      severity_filter: ["high", "critical"],
      phases: [1, 2, 3, 4],
      company_name: "Acme",
      current_phase: 3,
      vulns: [
        { id: "v1", title: "SQL Injection in /search", severity: "critical", endpoint: "https://acme.com/search?q=", cvss: 9.8, cve: "CVE-2024-1234" },
        { id: "v2", title: "Reflected XSS in /login", severity: "high", endpoint: "https://acme.com/login", cvss: 7.5 },
        { id: "v3", title: "Open Redirect on /go", severity: "medium", endpoint: "https://acme.com/go", cvss: 4.3 },
      ],
    },
    {
      id: "inst_02",
      name: "Globex bounty",
      targets: "globex.io",
      parent_target: "globex.io",
      status: "finished",
      started_at: nowIso(),
      finished_at: nowIso(),
      iterations: 80,
      tool_calls: 412,
      vuln_count: 2,
      total_tokens: 256_000,
      scan_mode: "balanced",
      company_name: "Globex",
      vulns: [
        { id: "v6", title: "S3 bucket misconfiguration", severity: "high", endpoint: "https://cdn.globex.io", cvss: 7.1 },
        { id: "v7", title: "Outdated jQuery 1.4.2", severity: "low", endpoint: "https://globex.io/static/jquery.js", cvss: 3.1 },
      ],
    },
  ],
  scans: [
    {
      id: "scan_01",
      name: "Acme nightly",
      target: "acme.com",
      parent_target: "acme.com",
      started_at: nowIso(),
      status: "running",
      scan_mode: "deep",
      instruction: "Standard",
      severity_filter: ["high", "critical"],
      vuln_count: 7,
      iterations: 42,
      tool_calls: 188,
      total_tokens: 124_000,
      current_phase: 3,
      phases: [1, 2, 3, 4],
    },
    {
      id: "scan_02",
      name: "Globex weekly",
      target: "globex.io",
      started_at: nowIso(),
      finished_at: nowIso(),
      status: "finished",
      scan_mode: "balanced",
      vuln_count: 2,
      iterations: 80,
      tool_calls: 412,
      total_tokens: 256_000,
    },
  ],
  queue: {
    available: true,
    targets: ["acme.com", "globex.io", "initech.com"],
    current_idx: 0,
    remaining: 2,
    instruction: "Standard recon + active probing",
    scan_mode: "deep",
    started_at: nowIso(),
  },
  resources: {
    cpu_cores: 8,
    cpu_load_1m: 1.23,
    ram_total_mb: 16_384,
    ram_available_mb: 9_216,
    disk_free_mb: 245_760,
    level: "healthy",
    reason: "",
    max_instances: 4,
    manual_max_instances: 4,
    effective_max_instances: 4,
  },
  rateLimit: { requests: 60, window: 60 },
  agentMail: { pod: "ops-pod-1", apiKey: "", hasApiKey: true },
  schedules: [],
  authProfiles: [],
  reqCounter: 0,
};

const providerCatalog = [
  { id: "openai", displayName: "OpenAI", baseURL: "https://api.openai.com/v1", headerStyle: "openai", authMethods: ["api_key"], models: ["gpt-5.6", "gpt-5.6-terra", "gpt-5.6-luna"] },
  { id: "google", displayName: "Google Gemini", baseURL: "https://generativelanguage.googleapis.com/v1beta", headerStyle: "gemini", authMethods: ["api_key"], models: ["gemini-3.5-flash", "gemini-3.6-flash"] },
];

const llmSettings = {
  model: "",
  apiBase: "",
  apiKey: "",
  hasApiKey: false,
  reasoningEffort: "high",
  ollamaCompatible: false,
  llmMaxRetries: 3,
  memoryCompressorTimeout: 120,
  maxIterations: 40,
  geminiApiKey: "",
  hasGeminiApiKey: false,
  envFile: "~/.xalgorix.env",
  provider: "",
  authMethod: "api_key",
  profiles: [],
};

// Flatten every seeded instance vuln into the FlatFinding shape the
// /findings page and Overview totals consume, so the list, the summary
// widget and the per-scan counts all agree.
function allFindings() {
  const out = [];
  for (const inst of state.instances) {
    for (const v of inst.vulns || []) {
      out.push({
        ...v,
        scan_id: inst.id,
        scan_target: inst.parent_target || inst.targets,
        scan_started_at: inst.started_at,
        verified: v.severity === "critical" || v.severity === "high",
        tags: [],
      });
    }
  }
  return out;
}

function findingsSummary() {
  const totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of allFindings()) {
    const sev = (f.severity || "").toLowerCase();
    if (sev in totals) totals[sev] += 1;
  }
  return {
    totals,
    as_of: nowIso(),
    etag: `mock-${totals.critical}${totals.high}${totals.medium}${totals.low}${totals.info}`,
  };
}

function runningInstance() {
  return state.instances.find((i) => i.status === "running");
}

function buildScanFromInstance(inst) {
  return {
    id: inst.id,
    name: inst.name,
    target: inst.targets,
    parent_target: inst.parent_target,
    started_at: inst.started_at,
    finished_at: inst.finished_at,
    status: inst.status,
    scan_mode: inst.scan_mode,
    instruction: inst.instruction,
    severity_filter: inst.severity_filter,
    phases: inst.phases,
    current_phase: inst.current_phase,
    company_name: inst.company_name,
    vuln_count: inst.vuln_count,
    iterations: inst.iterations,
    tool_calls: inst.tool_calls,
    total_tokens: inst.total_tokens,
  };
}

async function readBody(req) {
  return new Promise((resolve) => {
    let buf = "";
    req.on("data", (c) => (buf += c));
    req.on("end", () => {
      try {
        resolve(buf ? JSON.parse(buf) : {});
      } catch {
        resolve({});
      }
    });
  });
}

const server = http.createServer(async (req, res) => {
  const method = req.method || "GET";
  const url = req.url.split("?")[0];
  state.reqCounter += 1;

  // CORS preflight (the Vite dev server proxies same-origin so this is rarely
  // hit, but harmless to support).
  if (method === "OPTIONS") {
    res.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type",
    });
    return res.end();
  }

  // -------- Auth (auth disabled in the mock so login is bypassed) ----------
  if (method === "GET" && url === "/api/auth/status") {
    return send(res, { auth_enabled: false, authenticated: true });
  }
  if (method === "POST" && url === "/api/auth/login") {
    await readBody(req);
    return send(res, { status: "ok" });
  }
  if (method === "POST" && url === "/api/auth/logout") {
    return send(res, { status: "logged_out" });
  }

  // -------- Version / status ------------------------------------------------
  if (method === "GET" && url === "/api/version") {
    return send(res, { version: "4.2.9", commit: "dev" });
  }
  if (method === "GET" && url === "/api/status") {
    const run = runningInstance();
    return send(res, {
      running: !!run,
      scan_id: run ? `scan_${run.id.slice(-2)}` : "",
      instance_id: run?.id ?? "",
      current_phase: run?.current_phase ?? 0,
      vulns: run?.vuln_count ?? 0,
      running_instances: state.instances.filter((i) => i.status === "running")
        .length,
    });
  }

  // -------- Instances -------------------------------------------------------
  if (method === "GET" && url === "/api/instances") {
    return send(res, { instances: state.instances, resources: state.resources });
  }
  const instOne = url.match(/^\/api\/instances\/([^/]+)$/);
  if (instOne && method === "GET") {
    const inst = state.instances.find((i) => i.id === instOne[1]);
    return inst ? send(res, inst) : send(res, { error: "not found" }, 404);
  }
  const instStop = url.match(/^\/api\/instances\/([^/]+)\/stop$/);
  if (instStop && method === "POST") {
    const inst = state.instances.find((i) => i.id === instStop[1]);
    if (!inst) return send(res, { error: "not found" }, 404);
    inst.status = "finished";
    inst.finished_at = nowIso();
    inst.stop_reason = "manual";
    return ok(res, { status: "stopped" });
  }
  const instRestart = url.match(/^\/api\/instances\/([^/]+)\/restart$/);
  if (instRestart && method === "POST") {
    const inst = state.instances.find((i) => i.id === instRestart[1]);
    if (!inst) return send(res, { error: "not found" }, 404);
    inst.status = "running";
    inst.finished_at = undefined;
    inst.stop_reason = undefined;
    return ok(res, { status: "restarted" });
  }
  const instStart = url.match(/^\/api\/instances\/([^/]+)\/start$/);
  if (instStart && method === "POST") {
    const inst = state.instances.find((i) => i.id === instStart[1]);
    if (!inst) return send(res, { error: "not found" }, 404);
    inst.status = "running";
    inst.started_at = nowIso();
    return ok(res, { status: "started" });
  }

  // -------- Scans (records) -------------------------------------------------
  if (method === "GET" && url === "/api/scans") {
    return send(res, state.scans);
  }
  const scanOne = url.match(/^\/api\/scans\/([^/]+)$/);
  if (scanOne) {
    const id = scanOne[1];
    if (method === "DELETE") {
      const before = state.scans.length + state.instances.length;
      state.scans = state.scans.filter((s) => s.id !== id);
      state.instances = state.instances.filter((i) => i.id !== id);
      if (state.scans.length + state.instances.length === before) {
        return send(res, { error: "not found" }, 404);
      }
      return ok(res, { status: "deleted" });
    }
    if (method === "GET") {
      // Backend resolves /api/scans/{id} against both scan record ids
      // (scan_01) and live instance ids (inst_01). Mirror that.
      let scan = state.scans.find((s) => s.id === id);
      let inst = state.instances.find((i) => i.id === id);
      if (!scan && inst) scan = buildScanFromInstance(inst);
      if (!scan) return send(res, { error: "not found" }, 404);
      // Merge phases/vulns from the matching instance when available so the
      // scan-detail "Findings" tab is populated.
      if (!inst) inst = state.instances.find((i) => i.name === scan.name);
      const vulns =
        inst?.vulns ??
        (id === "scan_01"
          ? [
              { id: "v1", title: "SQL Injection in /search", severity: "critical", endpoint: "https://acme.com/search?q=", cvss: 9.8, cve: "CVE-2024-1234" },
              { id: "v2", title: "Reflected XSS in /login", severity: "high", endpoint: "https://acme.com/login", cvss: 7.5 },
              { id: "v3", title: "Open Redirect on /go", severity: "medium", endpoint: "https://acme.com/go", cvss: 4.3 },
              { id: "v4", title: "Verbose error in /api/v1/users", severity: "low", endpoint: "https://acme.com/api/v1/users", cvss: 2.0 },
              { id: "v5", title: "Missing security headers", severity: "info", endpoint: "https://acme.com/", cvss: 0 },
            ]
          : [
              { id: "v6", title: "S3 bucket misconfiguration", severity: "high", endpoint: "https://cdn.globex.io", cvss: 7.1 },
              { id: "v7", title: "Outdated jQuery 1.4.2", severity: "low", endpoint: "https://globex.io/static/jquery.js", cvss: 3.1 },
            ]);
      return send(res, { ...scan, events: [], vulns });
    }
  }

  // -------- Start a new scan -----------------------------------------------
  if (method === "POST" && (url === "/api/scan" || url === "/api/start")) {
    const body = await readBody(req);
    const targetsArr = Array.isArray(body.targets) ? body.targets : [];
    const primary = targetsArr[0] || "demo.local";
    const id = `inst_${String(state.instances.length + 1).padStart(2, "0")}`;
    const saveOnly = body.save_only === true;
    const newInst = {
      id,
      name: body.name || `Scan ${id}`,
      targets: targetsArr.join(",") || primary,
      parent_target: primary,
      status: saveOnly ? "saved" : "running",
      started_at: nowIso(),
      iterations: 0,
      tool_calls: 0,
      vuln_count: 0,
      total_tokens: 0,
      scan_mode: body.scan_mode || "single",
      instruction: body.instruction || "",
      severity_filter: body.severity_filter || [],
      phases: body.phases || [1, 2, 3, 4],
      company_name: body.company_name || "",
      current_phase: 1,
      vulns: [],
    };
    state.instances.unshift(newInst);
    state.scans.unshift({
      ...buildScanFromInstance(newInst),
      id: `scan_${String(state.scans.length + 1).padStart(2, "0")}`,
    });
    return ok(res, { status: saveOnly ? "saved" : "started", instance_id: id, id });
  }
  if (method === "POST" && url === "/api/stop") {
    for (const i of state.instances) {
      if (i.status === "running") {
        i.status = "finished";
        i.finished_at = nowIso();
        i.stop_reason = "stop_all";
      }
    }
    return ok(res, { status: "stopped" });
  }

  // -------- Queue -----------------------------------------------------------
  if (method === "GET" && url === "/api/queue/status") {
    return send(res, state.queue);
  }
  if (method === "POST" && url === "/api/queue/resume") {
    if (!state.queue.available) {
      return send(res, { status: "noop", error: "queue is empty" });
    }
    state.queue.current_idx = (state.queue.current_idx ?? 0) + 1;
    state.queue.remaining = Math.max(0, (state.queue.remaining ?? 0) - 1);
    return ok(res, {
      status: "resumed",
      from_index: state.queue.current_idx,
      targets_left: state.queue.remaining,
    });
  }
  if (method === "POST" && url === "/api/queue/clear") {
    state.queue = { available: false };
    return ok(res, { status: "cleared" });
  }

  // -------- Settings --------------------------------------------------------
  if (method === "GET" && url === "/api/settings/rate-limit") {
    return send(res, state.rateLimit);
  }
  if (method === "POST" && url === "/api/settings/rate-limit") {
    const body = await readBody(req);
    state.rateLimit = {
      requests: Number(body.requests) || state.rateLimit.requests,
      window: Number(body.window) || state.rateLimit.window,
    };
    return send(res, state.rateLimit);
  }
  if (method === "GET" && url === "/api/settings/agentmail") {
    return send(res, {
      pod: state.agentMail.pod,
      apiKey: "",
      hasApiKey: state.agentMail.hasApiKey,
    });
  }
  if (method === "POST" && url === "/api/settings/agentmail") {
    const body = await readBody(req);
    state.agentMail = {
      pod: typeof body.pod === "string" ? body.pod : state.agentMail.pod,
      apiKey: body.apiKey || state.agentMail.apiKey,
      hasApiKey: !!body.apiKey || state.agentMail.hasApiKey,
    };
    return send(res, {
      pod: state.agentMail.pod,
      apiKey: "",
      hasApiKey: state.agentMail.hasApiKey,
    });
  }

  // -------- Report download (anchor href in Reports page) -------------------
  const reportMatch = url.match(/^\/api\/report\/([^/]+)$/);
  if (reportMatch && method === "GET") {
    const id = reportMatch[1];
    const html = `<!doctype html><html><body style="font-family:sans-serif">
<h1>Xalgorix scan report</h1>
<p>Report for scan <code>${id}</code> (mock build).</p>
</body></html>`;
    return send(res, html, 200, { "content-type": "text/html; charset=utf-8" });
  }

  // -------- Chat (palette → ask) -------------------------------------------
  if (method === "POST" && url === "/api/chat") {
    await readBody(req);
    return send(res, {
      reply:
        "I am a mock assistant. The real backend would answer questions about the active scan here.",
    });
  }

  // -------- Findings list + on-disk summary --------------------------------
  if (method === "GET" && url === "/api/findings") {
    return send(res, allFindings());
  }
  if (method === "GET" && url === "/api/findings/summary") {
    return send(res, findingsSummary());
  }

  // -------- Per-instance persisted event history ---------------------------
  // The live feed streams over the WebSocket below; there is no synthetic
  // backlog, so return an empty (but valid) WSEvent[] history.
  if (method === "GET" && /^\/api\/instances\/[^/]+\/events$/.test(url)) {
    return send(res, []);
  }

  // -------- Schedules ------------------------------------------------------
  if (method === "GET" && url === "/api/schedules") {
    return send(res, state.schedules);
  }

  // -------- Provider catalog + stored auth profiles ------------------------
  if (method === "GET" && url === "/api/providers") {
    return send(res, providerCatalog);
  }
  if (method === "GET" && url === "/api/auth/profiles") {
    return send(res, state.authProfiles);
  }

  // -------- LLM / environment / legacy-import settings ---------------------
  if (method === "GET" && url === "/api/settings/llm") {
    return send(res, llmSettings);
  }
  if (method === "GET" && url === "/api/settings/environment") {
    return send(res, { envFile: "~/.xalgorix.env", variables: [], restartRequired: false });
  }
  if (method === "GET" && url === "/api/legacy-import/status") {
    return send(res, { count: 0, dismissed: true });
  }

  // Default. For an unhandled GET /api/* route fall back to an empty array
  // so a forgotten endpoint degrades to an empty collection instead of an
  // object that crashes array consumers with "(...).map is not a function".
  // Non-GET keeps the neutral ok envelope.
  if (method === "GET" && url.startsWith("/api/")) return send(res, []);
  send(res, { ok: true });
});

const port = Number(process.env.PORT || 8080);
server.listen(port, () => console.log(`mock backend on ${port}`));

// ---------------------------------------------------------------------------
// WebSocket: stream synthetic events to keep the live feed populated.
// ---------------------------------------------------------------------------
const wss = new WebSocketServer({ server, path: "/ws" });
wss.on("connection", (ws) => {
  let i = 0;
  const t = setInterval(() => {
    const run = runningInstance();
    if (!run) return; // pause the feed once everything is stopped
    const isEmail = i % 6 === 0;
    ws.send(
      JSON.stringify({
        type: isEmail ? "email_received" : "tool_call",
        content: isEmail
          ? "Email from attacker@evil.test triaged"
          : `nmap -sV ${run.parent_target || run.targets} probe ${i}`,
        tool_name: isEmail ? "agentmail" : "nmap",
        timestamp: nowIso(),
        agent_id: run.id,
        current_phase: run.current_phase,
      }),
    );
    i++;
  }, 1500);
  ws.on("close", () => clearInterval(t));
});

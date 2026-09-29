/*!
 * SiteSentinel — backend detection, alerting & auto-block engine (v1.0.0)
 * Zero npm dependencies. Node 18+.
 *
 * Standalone (demo):        node server.js          → http://localhost:8080
 * As a library/express middleware:
 *     const { createSentinel } = require("./server.js");
 *     const sentinel = createSentinel({ ...opts });
 *     app.use(sentinel.middleware);                  // protect every route
 *     sentinel.onAlert(a => sendEmail(...));         // hook your own alerting
 */
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;

function loadJson(p, fallback) {
  try { return JSON.parse(fs.readFileSync(path.join(ROOT, p), "utf8")); }
  catch (e) { return fallback; }
}

const DEFAULTS = {
  port: process.env.PORT || 8080,
  siteKey: process.env.SENTINEL_SITE_KEY || "demo-site-key",
  webhookUrl: process.env.SENTINEL_WEBHOOK || "",        // Slack/Discord/Telegram/Zapier — any URL accepting JSON POST
  ownerEmail: process.env.SENTINEL_OWNER_EMAIL || "",    // shown in dashboard + README
  mlThreshold: 30,         // NB log-odds above this => malicious (regex layer is primary)
  strikeThreshold: 3,      // strikes within rateWindowMs => auto-block
  rateWindowMs: 60000,
  blockTtlMs: 15 * 60 * 1000,
  criticalSignatures: ["sql_sleep_benchmark", "lfi_etc_passwd", "xss_js_uri", "lfi_php_wrapper", "scan_probe_tool", "poll_scan_probe"],
  maxBodyKb: 64
};

/* ------------------------------- detection engine ------------------------------- */

class SentinelEngine {
  constructor(model, signatures, opts, stopwords) {
    this.opts = opts;
    this.features = model.features;        // { ngram: [logP_attack, logP_benign] }
    this.prior = model.prior_attack;       // [logPriorAttack, logPriorBenign]
    this.tokenRe = /[a-z0-9]+|[^\sa-z0-9]/g;
    this.stop = new Set(stopwords || []);
    this.sigs = (signatures.signatures || [])
      .filter(s => (s.benign_hit_rate < 0.02 && s.lift >= 10) || s.name === "poll_scan_probe")
      .map(s => ({ name: s.name, re: new RegExp(s.regex, "i"), lift: s.lift }));
    this.modelMeta = { source: model.source, validation: model.validation, rows: signatures.rows };
  }

  /** URL-decode up to 2 rounds (payloads are often encoded/double-encoded) */
  decode(s) {
    let out = String(s);
    for (let i = 0; i < 2; i++) {
      let d;
      try { d = decodeURIComponent(out.replace(/\+/g, " ")); } catch (e) { break; }
      if (d === out) break;
      out = d;
    }
    return out;
  }

  /** token feature set from raw AND decoded text, structural tokens removed */
  docFeatures(text) {
    const feats = new Set();
    const variants = new Set([String(text).toLowerCase(), this.decode(text).toLowerCase()]);
    for (const v of variants) {
      const t = (v.match(this.tokenRe) || []).filter(x => !this.stop.has(x));
      for (const tok of t) feats.add(tok);
      for (let i = 0; i < t.length - 1; i++) feats.add(t[i] + " " + t[i + 1]);
    }
    return feats;
  }

  mlScore(text) {                       // >0 leans attack, <0 leans benign
    let sa = this.prior[0], sb = this.prior[1];
    for (const tok of this.docFeatures(text)) {
      const f = this.features[tok];
      if (f) { sa += f[0]; sb += f[1]; }
    }
    return sa - sb;
  }

  regexHits(text) {
    const variants = [String(text || ""), this.decode(String(text || ""))];
    const hits = [];
    for (const s of this.sigs)
      if (variants.some(v => s.re.test(v))) hits.push({ name: s.name, lift: s.lift });
    return hits;
  }

  /** Analyze one request text -> verdict + reasons. extraTexts are scanned
   *  by regex only (e.g. User-Agent: version tokens would poison the ML score) */
  analyze(text, extraTexts) {
    const t = String(text || "");
    const hits = this.regexHits(t);
    for (const x of extraTexts || []) for (const h of this.regexHits(String(x || ""))) hits.push(h);
    const seen = new Set(); const uniqHits = hits.filter(h => !seen.has(h.name) && seen.add(h.name));
    const ml = this.mlScore(t);
    const critical = hits.some(h => this.opts.criticalSignatures.includes(h.name));
    const strongHit = hits.some(h => h.lift >= 100);
    const malicious = critical || ml > this.opts.mlThreshold || (uniqHits.length >= 2 && ml > 0);
    const suspicious = !malicious && (uniqHits.length >= 1 || ml > 10);
    return {
      verdict: malicious ? "malicious" : suspicious ? "suspicious" : "clean",
      mlScore: Math.round(ml * 100) / 100,
      signatures: uniqHits.map(h => h.name),
      critical
    };
  }
}

/* ------------------------------ core (state + actions) -------------------------- */

function createSentinel(userOpts) {
  const opts = Object.assign({}, DEFAULTS, userOpts || {});
  const engine = new SentinelEngine(
    loadJson("model.json", { features: {}, prior_attack: [0, 0] }),
    loadJson("signatures.json", { signatures: [] }),
    opts,
    loadJson("stopwords.json", [])
  );

  const state = {
    startedAt: Date.now(),
    events: [],            // recent events (ring buffer)
    strikes: new Map(),     // ip -> [timestamps]
    blocked: new Map(),     // ip -> until
    alerts: [],
    stats: { total: 0, malicious: 0, suspicious: 0, blocked: 0, alerts: 0 }
  };
  const alertListeners = [];

  const prune = (arr, windowMs) => { const t = Date.now(); return arr.filter(x => t - x < windowMs); };

  function isBlocked(ip) {
    const until = state.blocked.get(ip);
    if (!until) return false;
    if (Date.now() > until) { state.blocked.delete(ip); return false; }
    return true;
  }

  function block(ip, reason, verdict) {
    state.blocked.set(ip, Date.now() + opts.blockTtlMs);
    state.stats.blocked++;
    sendAlert({
      kind: "AUTO_BLOCK",
      ip, reason,
      verdict: verdict || "malicious",
      action: `IP blocked for ${Math.round(opts.blockTtlMs / 60000)} minutes`,
      ts: Date.now()
    });
  }

  function recordStrike(ip, verdict, reason) {
    if (isBlocked(ip)) return;
    state.strikes.set(ip, prune(state.strikes.get(ip) || [], opts.rateWindowMs));
    if (verdict === "malicious") {
      const arr = state.strikes.get(ip);
      arr.push(Date.now());
      if (arr.length >= opts.strikeThreshold) { block(ip, reason || "strike threshold reached", verdict); return; }
    }
    state.strikes.set(ip, state.strikes.get(ip));
  }

  function sendAlert(alert) {
    alert.id = crypto.randomBytes(6).toString("hex");
    state.alerts.unshift(alert);
    if (state.alerts.length > 100) state.alerts.pop();
    state.stats.alerts++;
    // 1) listeners (email etc. — wire your own in createSentinel().onAlert)
    alertListeners.forEach(fn => { try { fn(alert); } catch (e) { /* user code */ } });
    // 2) webhook (Slack / Discord / Telegram / Zapier -> email)
    if (opts.webhookUrl) {
      const body = JSON.stringify({
        text: `🚨 SiteSentinel ${alert.kind}: ${alert.reason || ""} — ${alert.action || ""} (ip ${alert.ip || "?"})`,
        alert
      });
      const u = new URL(opts.webhookUrl);
      const req = http.request({ hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } }, () => {});
      req.on("error", () => {});
      req.end(body);
    }
    // 3) always: console + persistent log
    console.log(`[ALERT ${alert.id}] ${alert.kind} ${alert.verdict || ""} ip=${alert.ip || "-"} ${alert.reason || ""}`);
    try { fs.appendFileSync(path.join(ROOT, "alerts.log.jsonl"), JSON.stringify(alert) + "\n"); } catch (e) {}
  }

  function recordEvent(ev, ip) {
    state.stats.total++;
    if (state.events.unshift(Object.assign({ ip: ip || "unknown" }, ev)) > 200) state.events.pop();
  }

  /* ---- request -> text the model was trained on (method, url, headers, body) ---- */
  function requestToText(req, body) {
    let headerText = "";
    for (const [k, v] of Object.entries(req.headers || {})) {
      if (["referer", "cookie", "x-forwarded-for", "x-requested-with", "authorization"].includes(k))
        headerText += k + ": " + v + "\n";
    }
    return `${req.method || "GET"} ${req.url || ""} ${headerText} ${body || ""}`;
  }

  /* -------- shared core: analyze an already-collected request ---------- */
  function handleRequestText(req, res, ip, body, onClean) {
    const verdict = engine.analyze(requestToText(req, body), [req.headers && req.headers["user-agent"]]);
    if (verdict.verdict !== "clean") {
      recordEvent({ kind: "server_intercept", sig: verdict.signatures.join(","), ml: verdict.mlScore, verdict: verdict.verdict, url: req.url, ts: Date.now() }, ip);
      if (verdict.verdict === "suspicious") state.stats.suspicious++;
      if (verdict.verdict === "malicious") state.stats.malicious++;
      recordStrike(ip, verdict.verdict, verdict.signatures.join(","));
      if (verdict.verdict === "malicious" && (verdict.critical || verdict.signatures.length >= 2)) {
        block(ip, `server intercept: ${verdict.signatures.join(", ")} (ml=${verdict.mlScore})`, verdict.verdict);
      } else if (verdict.verdict === "malicious") {
        sendAlert({ kind: "ATTACK", ip, verdict: "malicious", reason: `${verdict.signatures.join(", ")} (ml=${verdict.mlScore})`, action: "request denied (403)", url: req.url, ts: Date.now() });
      }
      if (verdict.verdict === "malicious") {
        if (res && res.writeHead) res.writeHead(403, { "Content-Type": "application/json" });
        if (res && res.end) return res.end(JSON.stringify({ denied: true, reason: "malicious payload detected" }));
        return;
      }
    }
    if (typeof onClean === "function") onClean();
    else if (res && res.end && !res.headersSent) res.end("OK");
  }

  /* ------------------------- express-compatible middleware ------------------------ */
  function middleware(req, res, next) {
    const ip = String(req.headers["x-forwarded-for"] || (req.socket && req.socket.remoteAddress) || "").split(",")[0].trim();
    if (isBlocked(ip)) {
      if (res.writeHead) res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ blocked: true, message: "Blocked by SiteSentinel" }));
    }
    // If a body parser already consumed the stream (express + body-parser), use req.body
    if (req.body !== undefined) {
      const body = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
      return handleRequestText(req, res, ip, body, next);
    }
    if (req.readableEnded || !req.readable) return handleRequestText(req, res, ip, "", next);
    let chunks = []; let size = 0;
    req.on("data", c => { size += c.length; if (size <= opts.maxBodyKb * 1024) chunks.push(c); });
    req.on("end", () => handleRequestText(req, res, ip, Buffer.concat(chunks).toString("utf8"), next));
    req.on("error", () => handleRequestText(req, res, ip, "", next));
  }

  return {
    opts, engine, state, middleware, handleRequestText, block, isBlocked, sendAlert,
    onAlert(fn) { alertListeners.push(fn); },
    handleClientEvents(events, ip) {
      const acknowledged = [];
      for (const ev of Array.isArray(events) ? events : [events]) {
        if (!ev || !ev.sig) continue;
        const verdict = "suspicious";
        recordEvent({ kind: "client_report", sig: ev.sig, verdict, url: ev.url, field: ev.extra && ev.extra.field, snippet: ev.snippet, session: ev.session, ts: ev.ts || Date.now() }, ip);
        state.stats.suspicious++;
        recordStrike(ip, verdict, `client: ${ev.sig}`);
        if (opts.criticalSignatures.includes(ev.sig)) block(ip, `client report: ${ev.sig}`, "malicious");
        else acknowledged.push(ev.sig);
        if (state.stats.suspicious % 10 === 1) {
          sendAlert({ kind: "CLIENT_ACTIVITY", ip, verdict, reason: `browser module reported ${ev.sig}`, action: "monitoring — no block yet (raise thresholds in config)", url: ev.url, ts: Date.now() });
        }
      }
      return acknowledged;
    }
  };
}

/* --------------------------------- standalone server ----------------------------- */

if (require.main === module) {
  const fileCfg = loadJson("config.json", {});
  const opts = Object.assign({}, DEFAULTS, fileCfg);
  if (process.env.PORT) opts.port = parseInt(process.env.PORT, 10);   // env always wins
  const sentinel = createSentinel(opts);
  const { engine, state } = sentinel;

  const MIME = { ".html": "text/html", ".js": "application/javascript", ".json": "application/json", ".css": "text/css" };

  const server = http.createServer((req, res) => {
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    const url = (req.url || "/").split("?")[0];

    if (isBlockedNow(ip)) return res.writeHead(403, { "Content-Type": "application/json" }).end(JSON.stringify({ blocked: true, message: "Blocked by SiteSentinel" }));
    function isBlockedNow(ip) { return sentinel.isBlocked(ip); }

    let chunks = []; let size = 0;
    req.on("data", c => { size += c.length; if (size <= opts.maxBodyKb * 1024) chunks.push(c); });
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");

      // --- ingest endpoint for the browser module -------------------------
      if (req.method === "POST" && url === "/sentinel/events") {
        try {
          const payload = JSON.parse(body || "{}");
          if (payload.siteKey && payload.siteKey !== opts.siteKey) { res.writeHead(401); return res.end('{"error":"bad siteKey"}'); }
          const ack = sentinel.handleClientEvents(payload.events, ip);
          res.writeHead(200, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ ok: true, acknowledged: ack }));
        } catch (e) { res.writeHead(400); return res.end('{"error":"bad json"}'); }
      }

      // --- JSON API ---------------------------------------------------------
      if (url === "/sentinel/stats") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
          stats: state.stats, uptimeSec: Math.round((Date.now() - state.startedAt) / 1000),
          blockedIps: [...state.blocked.keys()], model: engine.modelMeta,
          recentEvents: state.events.slice(0, 50), recentAlerts: state.alerts.slice(0, 20)
        }, null, 1));
      }

      // --- protect the demo API ---------------------------------------------
      if (url.startsWith("/api/")) {
        if (sentinel.isBlocked(ip)) { res.writeHead(403, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ blocked: true, message: "Blocked by SiteSentinel" })); }
        return sentinel.handleRequestText(req, res, ip, body, () => {
          if (url === "/api/search") {
            const q = decodeURIComponent((req.url.split("q=")[1] || "").split("&")[0]);
            res.writeHead(200, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ results: [{ title: "Result for " + q.slice(0, 50), safe: true }] }));
          }
          res.writeHead(404); res.end();
        });
      }

      // --- static files (demo) ----------------------------------------------
      const file = url === "/" ? "demo.html" : url.replace(/^\//, "");
      if (["demo.html", "sentinel.js", "model.json", "signatures.json"].includes(file)) {
        try {
          const data = fs.readFileSync(path.join(ROOT, file));
          res.writeHead(200, { "Content-Type": MIME[path.extname(file)] || "text/plain" });
          return res.end(data);
        } catch (e) { res.writeHead(404); return res.end("not found"); }
      }

      if (url === "/sentinel/dashboard") {
        const html = fs.readFileSync(path.join(ROOT, "dashboard.html"), "utf8");
        res.writeHead(200, { "Content-Type": "text/html" });
        return res.end(html);
      }

      res.writeHead(404); res.end();
    });
  });

  server.listen(opts.port, () => {
    console.log(`SiteSentinel running on http://localhost:${opts.port}`);
    console.log(`  demo site       -> http://localhost:${opts.port}/  (demo.html + sentinel.js)`);
    console.log(`  dashboard       -> http://localhost:${opts.port}/sentinel/dashboard`);
    console.log(`  stats API       -> http://localhost:${opts.port}/sentinel/stats`);
    console.log(`  event ingest    -> POST /sentinel/events   (siteKey: ${opts.siteKey})`);
    console.log(`  model           -> trained on ${engine.modelMeta.source}`);
    console.log(`  validation      -> precision ${engine.modelMeta.validation.precision}, recall ${engine.modelMeta.validation.recall}`);
    if (opts.webhookUrl) console.log(`  webhook alerts  -> ${opts.webhookUrl}`);
    else console.log(`  webhook alerts  -> not configured (set webhookUrl in config.json)`);
  });
}

module.exports = { createSentinel, SentinelEngine, DEFAULTS };

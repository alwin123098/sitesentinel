/**
 * SiteSentinel smoke tests — no network, no server needed.
 * Verifies the detection engine behaves correctly on known-benign and
 * known-attack inputs. Run with: npm test
 */
"use strict";
const assert = require("assert");
const path = require("path");
const { createSentinel } = require(path.join(__dirname, "..", "server.js"));

const sentinel = createSentinel(require(path.join(__dirname, "..", "config.json")));
const engine = sentinel.engine;

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";

function check(name, text, ua, expect) {
  const v = engine.analyze(text, [ua || UA]);
  assert.strictEqual(v.verdict, expect, `${name}: expected "${expect}" got "${v.verdict}" (ml=${v.mlScore}, sigs=${v.signatures})`);
  console.log(`  ok  ${name} -> ${v.verdict}${v.signatures.length ? " [" + v.signatures.join(",") + "]" : ""}`);
}

let passed = 0, failed = 0;
const tests = [
  ["benign: plain search query", "GET /api/search?q=wireless%20mouse", UA, "clean"],
  ["benign: long natural query", "GET /api/search?q=best%20running%20shoes%20under%202000", UA, "clean"],
  ["benign: page navigation", "GET /about", UA, "clean"],
  ["attack: SQL tautology", "GET /api/search?q=gift%27%20OR%201%3D1--", UA, "malicious"],
  ["attack: XSS script tag", "GET /api/search?q=%3Cscript%3Ealert(1)%3C/script%3E", UA, "malicious"],
  ["attack: blind SQL (SLEEP)", "GET /api/search?q=1%27%20AND%20SLEEP(5)--", UA, "malicious"],
  ["attack: path traversal", "GET /api/search?q=../../etc/passwd", UA, "malicious"],
  ["attack: UNION SELECT", "GET /api/search?q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--", UA, "malicious"],
  ["attack: img onerror XSS", "GET /q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", UA, "malicious"],
  ["attack: javascript URI", "GET /q=javascript%3Aalert(document.domain)", UA, "malicious"],
  ["attack: double-encoded XSS", "GET /q=%253Cscript%253Ealert(1)%253C%252Fscript%253E", UA, "malicious"],
  ["attack: sqlmap scanner UA", "GET /x", "sqlmap/1.7.11#stable (https://sqlmap.org)", "malicious"],
  ["attack: nikto scanner UA", "GET /x", "Mozilla/5.0 Nikto/2.5.0", "malicious"],
];

// --- engine verdicts ---
console.log("engine verdicts:");
for (const [name, text, ua, expect] of tests) {
  try { check(name, text, ua, expect); passed++; } catch (e) { failed++; console.log("  FAIL", e.message); }
}

// --- client-event handling: critical client report auto-blocks ---
console.log("auto-block on critical client report:");
try {
  const ip = "203.0.113.99";
  sentinel.handleClientEvents([{ sig: "sql_sleep_benchmark", snippet: "sleep(5)", url: "http://t/", ts: Date.now() }], ip);
  assert.ok(sentinel.isBlocked(ip), "critical client report should block IP");
  console.log("  ok  critical client report blocks source IP");
  passed++;
} catch (e) { failed++; console.log("  FAIL", e.message); }

// --- middleware: benign passes, attack denied ---
console.log("middleware:");
{
  const mkRes = () => ({ headersSent: false, status: 0, body: "", writeHead(c) { this.status = c; return this; }, end(b) { this.body = b; this.headersSent = true; return this; } });
  const mkReq = (url) => ({ method: "GET", url, headers: { "user-agent": UA, "x-forwarded-for": "198.51.100.1" }, socket: { remoteAddress: "198.51.100.1" }, on() {}, readableEnded: true, readable: false });
  try {
    const res = mkRes(); let called = false;
    sentinel.middleware(mkReq("/api/search?q=hello"), res, () => { called = true; });
    assert.ok(called, "benign request should reach next()");
    console.log("  ok  benign request passes through");
    passed++;
  } catch (e) { failed++; console.log("  FAIL", e.message); }
  try {
    const res = mkRes();
    sentinel.middleware(mkReq("/api/search?q=1%27%20OR%201%3D1--"), res, null);
    assert.strictEqual(res.status, 403, "attack request should be denied with 403");
    console.log("  ok  attack request denied with 403");
    passed++;
  } catch (e) { failed++; console.log("  FAIL", e.message); }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

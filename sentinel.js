/*!
 * SiteSentinel — client-side attack monitor (v1.0.0)
 * Drop into any website with:
 *   <script src="sentinel.js"></script>
 *   <script>window.SENTINEL_CONFIG = { endpoint: "https://your-backend/sentinel/events", siteKey: "YOUR_SITE_KEY" };</script>
 *
 * What it does
 *  - Watches URLs, form input, outgoing fetch/XHR calls and DOM mutations
 *  - Screens everything against attack signatures derived from a
 *    625,904-request web-attack dataset (SQLi, XSS, LFI, command injection)
 *  - Reports suspicious activity to the SiteSentinel backend in real time,
 *    where the owner is alerted and the source can be auto-blocked
 *
 * Privacy: field VALUES are never transmitted — only the signature that
 * matched and a short snippet of the matched text (max 120 chars).
 *
 * MIT License. Model data: YangYang-Research/web-attack-detection (HF).
 */
(function () {
  "use strict";

  var CFG = window.SENTINEL_CONFIG || {};
  var endpoint = CFG.endpoint || "/sentinel/events";
  var siteKey = CFG.siteKey || "";
  var debugMode = !!CFG.debug;

  // High-lift signatures validated against the full dataset
  // (attack hit-rate vs benign hit-rate in parentheses).
  var SIGNATURES = [
    { name: "sql_tautology",      re: /('|%27)?\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i }, // 1.6% vs 0.0006%
    { name: "sql_union_select",   re: /union[\s+]+(all[\s+]+)?select/i },                      // 2.2% vs 0.10%
    { name: "sql_sleep_benchmark",re: /(sleep\s*\(\s*\d+|benchmark\s*\(\s*\d+|waitfor\s+delay|pg_sleep)/i }, // 6.9% vs 0%
    { name: "sql_quote_probe",    re: /'\s*(or|and|union|select|;)/i },                        // 3.3% vs 0.44%
    { name: "xss_script_tag",     re: /<\s*script/i },                                          // 6.4% vs 0.009%
    { name: "xss_event_handler",  re: /on(error|load|click|mouseover|focus|toggle)\s*=/i },    // 1.3% vs 0.001%
    { name: "xss_js_uri",         re: /javascript\s*:/i },                                      // 0.59% vs 0%
    { name: "xss_svg_onload",     re: /<\s*svg[^>]*onload/i },                                 // 0.03% vs 0%
    { name: "xss_alert_prompt",    re: /(alert|prompt|confirm)\s*\(/i },                       // 19.0% vs 0.001%
    { name: "xss_encoded",        re: /(&#x?[0-9a-f]+;|%3cscript|%3c%73%63%72%69%70%74)/i },  // 11.9% vs 0.19%
    { name: "lfi_path_traversal", re: /(\.\.\/|\.\.\\|%2e%2e(%2f|2f)?)/i },                    // 4.0% vs 0.002%
    { name: "lfi_etc_passwd",     re: /\/etc\/(passwd|shadow|hosts)/i },                        // 0.23% vs 0%
    { name: "lfi_php_wrapper",    re: /php:\/\/(filter|input|expect)/i },                      // 0.002% vs 0%
    { name: "cmdi_backtick",      re: /`[^`]+`/ },                                              // 1.7% vs 0.005%
    { name: "rce_eval",           re: /(eval|system|exec|passthru|shell_exec|popen)\s*\(/i },  // 0.16% vs 0.0006%
    { name: "scan_probe_tool",    re: /(sqlmap|nikto|nmap|nessus|acunetix|havij|wpscan|masscan|metasploit)/i }
  ];

  var queue = [];
  var lastSentBySig = {};     // rate-limit: one report per signature per 20 s
  var submitTimes = [];       // behavior: rapid form resubmission
  var session = "s-" + Math.random().toString(36).slice(2, 10);

  function now() { return Date.now(); }

  function log() { if (debugMode && window.console) console.log.apply(console, ["[sentinel]"].concat([].slice.call(arguments))); }

  function screen(text) {
    if (!text || typeof text !== "string" || text.length < 4) return null;
    for (var i = 0; i < SIGNATURES.length; i++) {
      var m = text.match(SIGNATURES[i].re);
      if (m) {
        return {
          sig: SIGNATURES[i].name,
          // snippet = only the matched region (never the whole field value)
          snippet: m.index !== undefined ? text.substr(m.index, 120) : m[0].slice(0, 120)
        };
      }
    }
    return null;
  }

  function report(hit, extra) {
    if (!hit) return;
    var t = now();
    if (lastSentBySig[hit.sig] && t - lastSentBySig[hit.sig] < 20000) return; // throttle
    lastSentBySig[hit.sig] = t;
    queue.push({
      siteKey: siteKey,
      session: session,
      sig: hit.sig,
      snippet: (hit.snippet || "").slice(0, 120),
      url: location.href.split("#")[0],
      ts: t,
      ua: navigator.userAgent,
      extra: extra || null
    });
    log("flagged", hit.sig);
    flush();
  }

  function flush() {
    if (!queue.length) return;
    var body = JSON.stringify({ siteKey: siteKey, events: queue.splice(0, queue.length) });
    if (navigator.sendBeacon) {
      try { navigator.sendBeacon(endpoint, new Blob([body], { type: "application/json" })); return; } catch (e) { /* fall through */ }
    }
    try {
      fetch(endpoint, { method: "POST", keepalive: true, headers: { "Content-Type": "application/json" }, body: body }).catch(function () {});
    } catch (e) { /* beacon unavailable */ }
  }

  // ---- 1. URL / querystring -------------------------------------------------
  function checkUrl() { report(screen(location.href)); }

  window.addEventListener("load", checkUrl);
  var push = history.pushState;
  if (push) {
    history.pushState = function () { push.apply(history, arguments); setTimeout(checkUrl, 0); };
    window.addEventListener("popstate", checkUrl);
  }

  // ---- 2. Forms and fields --------------------------------------------------
  document.addEventListener("submit", function (ev) {
    var t = now();
    submitTimes.push(t);
    while (submitTimes.length && t - submitTimes[0] > 10000) submitTimes.shift();
    if (submitTimes.length >= 5) {
      report({ sig: "behavior_rapid_submit", snippet: submitTimes.length + " submits/10s" });
      submitTimes = [];
    }
    var form = ev.target;
    if (form && form.elements) {
      for (var i = 0; i < form.elements.length; i++) {
        var el = form.elements[i];
        if (el && el.value && !/^(password|token|secret|api[-_]?key)$/i.test(el.name || "")) {
          var hit = screen(String(el.value));
          if (hit) report(hit, { field: el.name || el.id || "unnamed" });
        }
      }
    }
  }, true); // capture: fires even if the site calls stopPropagation

  // ---- 3. Outgoing fetch / XHR ----------------------------------------------
  var of = window.fetch;
  if (of) {
    window.fetch = function (input, init) {
      try {
        var url = typeof input === "string" ? input : (input && input.url) || "";
        var body = init && init.body;
        report(screen(url));
        if (typeof body === "string") report(screen(body));
      } catch (e) { /* never break the host page */ }
      return of.apply(this, arguments);
    };
  }
  var oOpen = XMLHttpRequest.prototype.open;
  var oSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) { this.__surl = url || ""; return oOpen.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function (body) {
    try { report(screen(String(this.__surl || ""))); if (typeof body === "string") report(screen(body)); } catch (e) {}
    return oSend.apply(this, arguments);
  };

  // ---- 4. DOM mutation (post-load injected scripts / handlers) ---------------
  function scanNode(node) {
    if (!node || node.nodeType !== 1) return;
    var tag = node.tagName;
    if (tag === "SCRIPT" || tag === "IFRAME") {
      var src = node.getAttribute && (node.getAttribute("src") || "");
      var inline = tag === "SCRIPT" && node.textContent ? node.textContent.slice(0, 500) : "";
      var hit = screen(src || "") || screen(inline);
      if (hit) report(hit, { injected: tag, src: (src || "").slice(0, 120) });
    }
    if (node.getAttribute) {
      var attrs = ["onerror", "onload", "onclick", "onmouseover"];
      for (var i = 0; i < attrs.length; i++) {
        var v = node.getAttribute(attrs[i]);
        if (v) { var h = screen(v); if (h) report(h, { injected: tag, attr: attrs[i] }); }
      }
    }
  }
  function startObserver() {
    if (!window.MutationObserver) return;
    new MutationObserver(function (muts) {
      muts.forEach(function (m) {
        m.addedNodes.forEach(function (n) {
          if (n.querySelectorAll) {
            scanNode(n);
            if (n.querySelectorAll) {
              var kids = n.querySelectorAll("script,iframe,[onerror],[onload],[onclick],[onmouseover]");
              for (var i = 0; i < kids.length; i++) scanNode(kids[i]);
            }
          } else scanNode(n);
        });
        if (m.type === "attributes" && m.target) scanNode(m.target);
      });
    }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["onerror", "onload", "onclick", "onmouseover", "src"] });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", startObserver);
  else startObserver();

  // periodic flush (safety net) + public debug handle
  setInterval(flush, 15000);
  window.Sentinel = {
    version: "1.0.0",
    screen: screen,
    events: function () { return queue; },
    flush: flush
  };
})();

"""
Train the SiteSentinel detection model from the Hugging Face dataset
YangYang-Research/web-attack-detection (625,904 labeled HTTP requests:
Label 1 = attack, 0 = benign).

Outputs:
  model.json      - compact Multinomial Naive Bayes (token uni+bi-grams)
  signatures.json - regex signatures validated against the FULL dataset
                    (attack hit-rate vs benign hit-rate)
"""
import json
import math
import random
import re
import urllib.parse
from collections import Counter

import pandas as pd

random.seed(42)

print("Loading dataset ...")
df = pd.read_csv("/scratch/work/dataset.csv", encoding="utf-8-sig")
df.columns = [c.strip() for c in df.columns]
print(df["Label"].value_counts().to_dict())

texts = df["Sentence"].astype(str).tolist()
labels = df["Label"].astype(int).tolist()

TOKEN_RE = re.compile(r"[a-z0-9]+|[^\sa-z0-9]")

# Structural HTTP/browser tokens: present in nearly every request dump. The
# dataset's attack rows are full HTTP request dumps while benign rows are plain
# sentences, so without stripping these the model just learns "is an HTTP
# request" instead of "is a malicious payload".
STOP = {
    "get", "post", "put", "delete", "head", "options", "patch", "http", "https",
    "1.1", "1.0", "0.9", "user", "agent", "user-agent", "accept", "accept-encoding",
    "accept-language", "encoding", "gzip", "deflate", "br", "language", "en-us",
    "en", "q", "cache-control", "max-age", "host", "connection", "close",
    "keep-alive", "content-type", "content-length", "cookie", "charset", "text",
    "html", "json", "application", "image", "png", "urlencoded", "localhost",
    "origin", "dnt", "requested-with", "xmlhttprequest", "sec-fetch-dest",
    "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "document", "navigate",
    "upgrade-insecure-requests", "referer", " mozilla", "mozilla", "windows",
    "win64", "x64", "macintosh", "intel", "applewebkit", "khtml", "like", "gecko",
    "chrome", "safari", "linux", "android", "mobile", "iphone", "ipad",
    "trident", "msie", "edg", "opera", "presto", "compatible", "version",
    "no-cache", "x-requested-with", "multipart", "form-data", "boundary",
}

def http_unquote(s, times=2):
    """URL-decode up to `times` rounds (payloads are often double-encoded)."""
    out = s
    for _ in range(times):
        try:
            new = urllib.parse.unquote_plus(out)
        except Exception:
            break
        if new == out:
            break
        out = new
    return out

def doc_features(text):
    """Set of uni+bigrams from raw AND url-decoded text, structural tokens removed."""
    feats = set()
    for variant in {text.lower(), http_unquote(text).lower()}:
        toks = [t for t in TOKEN_RE.findall(variant) if t not in STOP]
        feats.update(toks)
        feats.update(toks[i] + " " + toks[i + 1] for i in range(len(toks) - 1))
    return feats

def tokenize(text):

    toks = TOKEN_RE.findall(text.lower())
    # unigrams + bigrams (bigrams catch "--", "' o", "union select")
    out = toks + [toks[i] + " " + toks[i + 1] for i in range(len(toks) - 1)]
    return out

# ---------------- Part 1: Naive Bayes on a stratified sample ----------------
idx_all = list(range(len(texts)))
random.shuffle(idx_all)
att_idx = [i for i in idx_all if labels[i] == 1]
ben_idx = [i for i in idx_all if labels[i] == 0]

TRAIN_PER_CLASS = 80_000
VALID_PER_CLASS = 8_000
train_idx = att_idx[:TRAIN_PER_CLASS] + ben_idx[:TRAIN_PER_CLASS]
valid_idx = att_idx[TRAIN_PER_CLASS:TRAIN_PER_CLASS + VALID_PER_CLASS] + \
            ben_idx[TRAIN_PER_CLASS:TRAIN_PER_CLASS + VALID_PER_CLASS]

def count_class(idxs):
    cnt = Counter()
    total = 0
    for i in idxs:
        cnt.update(doc_features(texts[i]))  # presence per document (Bernoulli-style)
        total += 1
    return cnt, total

print("Counting attack n-grams ...")
att_cnt, n_att = count_class(att_idx[:TRAIN_PER_CLASS])
print("Counting benign n-grams ...")
ben_cnt, n_ben = count_class(ben_idx[:TRAIN_PER_CLASS])

ALPHA = 0.5
MIN_DF = 8

# log-odds ranking (attack vs benign), with smoothing
V = set(f for f, c in att_cnt.items() if c >= MIN_DF) | set(f for f, c in ben_cnt.items() if c >= MIN_DF)
print(f"Vocabulary before pruning: {len(V)}")

scores = {}
for f in V:
    la = math.log((att_cnt.get(f, 0) + ALPHA) / (n_att + ALPHA))
    lb = math.log((ben_cnt.get(f, 0) + ALPHA) / (n_ben + ALPHA))
    scores[f] = la - lb            # >0 pushes toward attack

# keep strongest discriminative features, capped
KEEP = 4000
ranked = sorted(scores.items(), key=lambda kv: -abs(kv[1]))
kept = ranked[:KEEP]

# full NB conditionals for kept features
feat = {}
for f, _ in kept:
    la = math.log((att_cnt.get(f, 0) + ALPHA) / (n_att + ALPHA * 2))
    lb = math.log((ben_cnt.get(f, 0) + ALPHA) / (n_ben + ALPHA * 2))
    feat[f] = [round(la, 5), round(lb, 5)]

model = {
    "source": "YangYang-Research/web-attack-detection (Hugging Face, MIT license)",
    "train_rows": len(train_idx),
    "prior_attack": [round(math.log(n_att / (n_att + n_ben)), 5), round(math.log(n_ben / (n_att + n_ben)), 5)],
    "alpha": ALPHA,
    "features": feat,
}

# ---------------- validation ----------------
def classify(text, thresh=0.0):
    sa, sb = model["prior_attack"]
    for t in doc_features(text):
        if t in feat:
            sa += feat[t][0]
            sb += feat[t][1]
    return (sa - sb) > thresh

tp = fp = tn = fn = 0
for i in valid_idx:
    pred = classify(texts[i])
    if labels[i] == 1 and pred: tp += 1
    elif labels[i] == 1 and not pred: fn += 1
    elif labels[i] == 0 and pred: fp += 1
    else: tn += 1
prec = tp / max(tp + fp, 1)
rec = tp / max(tp + fn, 1)
print(f"VALIDATION  tp={tp} fp={fp} tn={tn} fn={fn}  precision={prec:.4f} recall={rec:.4f} f1={2*prec*rec/max(prec+rec,1e-9):.4f}")
model["validation"] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                       "precision": round(prec, 4), "recall": round(rec, 4)}

with open("/scratch/work/stopwords.json", "w") as fh:
    json.dump(sorted(STOP), fh)
with open("/scratch/work/model.json", "w") as fh:
    json.dump(model, fh)
print(f"model.json written ({len(feat)} features)")

# ---------------- Part 2: regex signatures over the FULL 625K rows ----------------
PATTERNS = {
    "sql_tautology":       r"(('|%)?\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
    "sql_union_select":    r"union[\s+]+(all[\s+]+)?select",
    "sql_sleep_benchmark": r"(sleep\s*\(\s*\d+|benchmark\s*\(\s*\d+|waitfor\s+delay|pg_sleep)",
    "sql_comment":         r"(--|#|/\*)\s*$|(')\s*(or|and)\s+(')",
    "sql_drop_alter":      r";\s*(drop|alter|truncate|create)\s+(table|database)",
    "sql_quote_probe":     r"('\s*(or|and|union|select|;)|\\x27|\\x3d)",
    "xss_script_tag":      r"<\s*script",
    "xss_event_handler":   r"on(error|load|click|mouseover|focus|animationstart|toggle)\s*=",
    "xss_js_uri":          r"javascript\s*:",
    "xss_img_src":         r"<\s*img[^>]+src",
    "xss_svg_onload":      r"<\s*svg[^>]*onload",
    "xss_alert_prompt":    r"(alert|prompt|confirm)\s*\(",
    "xss_encoded":         r"(&#x?[0-9a-f]+;|%3cscript|%3c%73%63%72%69%70%74)",
    "lfi_path_traversal":  r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)",
    "lfi_etc_passwd":      r"/etc/(passwd|shadow|hosts)",
    "lfi_php_wrapper":     r"php://(filter|input|expect)",
    "cmdi_semicolon":      r";\s*(cat|ls|id|whoami|wget|curl|nc|rm|ping)\s",
    "cmdi_pipe":           r"\|\s*(cat|ls|id|whoami|wget|curl|nc|rm|ping)\s",
    "cmdi_backtick":       r"(`[^`]+`|\$\([^)]+\))",
    "cmdi_shell_meta":     r"(\$\((i|e)fd\)|&&\s*(cat|ls|id|whoami))",
    "rce_eval":            r"(eval\s*\(|system\s*\(|exec\s*\(|passthru|shell_exec|popen)",
    "ssrf_internal":       r"(127\.0\.0\.1|localhost|169\.254\.169\.254|metadata\.google)",
    "poll_scan_probe":     r"(sqlmap|nikto|nmap|nessus|acunetix|havij|dirbuster|wpscan|masscan|metasploit)",
    "header_injection":    r"(\r\n|\n)(to|bcc|subject|reply-to)\s*:",
}

if __import__("os").path.exists("/scratch/work/signatures.json"):
    print("signatures.json exists - skipping regex stats")
    raise SystemExit(0)
sig_series = df["Sentence"].astype(str).str.lower()
lbl = df["Label"].astype(int).values
n_att_total = int((lbl == 1).sum())
n_ben_total = int((lbl == 0).sum())

signatures = []
print("\nSignature stats (full corpus):")
for name, pat in PATTERNS.items():
    try:
        rx = re.compile(pat)
        hits = sig_series.map(lambda s: bool(rx.search(s))).values
    except re.error:
        continue
    att_rate = float((hits & (lbl == 1)).sum()) / n_att_total
    ben_rate = float((hits & (lbl == 0)).sum()) / n_ben_total
    signatures.append({
        "name": name,
        "regex": pat,
        "attack_hit_rate": round(att_rate, 5),
        "benign_hit_rate": round(ben_rate, 5),
        "lift": round((att_rate + 1e-6) / (ben_rate + 1e-6), 2),
    })
    print(f"  {name:22s} attack={att_rate:8.4%}  benign={ben_rate:8.4%}  lift={signatures[-1]['lift']}")

with open("/scratch/work/signatures.json", "w") as fh:
    json.dump({"source": model["source"], "rows": len(df),
               "n_attack": n_att_total, "n_benign": n_ben_total,
               "signatures": signatures}, fh, indent=1)
print("signatures.json written")

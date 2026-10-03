"""Bounded heuristic request inspection. Not a WAF or security guarantee."""
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import unquote_plus
import re

@dataclass(frozen=True)
class RequestData:
    method: str
    path: str
    query_string: str = ""
    headers: Mapping[str, str] | None = None
    body: bytes = b""

@dataclass(frozen=True)
class Finding:
    category: str
    rule_id: str
    severity: str
    evidence: str = "pattern matched"

@dataclass(frozen=True)
class Inspection:
    findings: tuple[Finding, ...]
    @property
    def suspicious(self): return bool(self.findings)
    @property
    def categories(self): return tuple(dict.fromkeys(f.category for f in self.findings))

_RULES = (
 ("sqli","sql_union_select","high",r"\bunion\s+(?:all\s+)?select\b"),
 ("sqli","sql_tautology","medium",r"""\bor\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?"""),
 ("sqli","sql_comment","low",r"(?:--\s|/\*|\*/|#)"),
 ("xss","html_script_tag","high",r"<\s*script\b"),
 ("xss","html_event_handler","medium",r"""\bon\w+\s*=\s*(?:['"]|[^\s>]+)"""),
 ("xss","javascript_url","medium",r"""\b(?:javascript|vbscript)\s*:"""),
 ("lfi","path_traversal","high",r"(?:\.\.[/\\]){2,}"),
 ("lfi","sensitive_file","medium",r"/(?:etc/passwd|proc/self/environ|windows/win\.ini)\b"),
 ("cmdi","shell_operator","medium",r"(?:\|\||&&|[;|]\s*)(?:sh|bash|cmd|powershell|curl|wget)\b"),
 ("cmdi","shell_substitution","high",r"\$\([^)]{1,160}\)"),
)
_COMPILED = tuple((c,i,s,re.compile(p,re.I)) for c,i,s,p in _RULES)

class Inspector:
    def __init__(self, *, max_body_bytes=16384, max_component_chars=8192):
        if max_body_bytes < 0 or max_component_chars < 1: raise ValueError("invalid limits")
        self.max_body_bytes, self.max_component_chars = max_body_bytes, max_component_chars
    def inspect(self, request: RequestData) -> Inspection:
        body = request.body[:self.max_body_bytes].decode("utf-8", errors="replace")
        headers = request.headers or {}
        text = "\n".join((request.method, request.path, request.query_string, body, " ".join(map(str, headers.values()))))
        text = text[:self.max_component_chars * 5]
        for _ in range(2):
            decoded = unquote_plus(text, errors="replace")
            if decoded == text: break
            text = decoded[:self.max_component_chars * 5]
        return Inspection(tuple(Finding(c,i,s) for c,i,s,p in _COMPILED if p.search(text)))

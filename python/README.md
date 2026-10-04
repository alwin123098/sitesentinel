# SiteSentinel Python integration

Dependency-free request inspection adapters for WSGI and ASGI. Install from this directory with python -m pip install .

Use WSGIMiddleware(your_wsgi_app) or ASGIMiddleware(your_asgi_app). Alerts receive rule IDs and categories only. Blocking is disabled unless block=True and an explicit should_block policy both allow it.

The detector uses bounded heuristic indicators. It is not the separately trained model and has false positives and false negatives. Begin in observe-only mode and review traffic before enforcement. Request inspection does not replace parameterized SQL, context-aware output encoding, safe file APIs, CSRF protection, least privilege, or framework controls. Enforce body sizes and timeouts at the server. Trust forwarded IP headers only from configured proxies. Alert delivery, persistent auto-bans, model downloads, and universal framework support are not included. Review and load-test in the target deployment; no security guarantee is made.

MIT license; see repository LICENSE.

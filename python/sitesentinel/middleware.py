"""Minimal WSGI and ASGI adapters; blocking is opt-in."""
import json
from .core import Inspector, RequestData

class _PrefixedStream:
    """Replay inspected bytes, then continue from the original WSGI stream."""
    def __init__(self, prefix, stream):
        self.prefix = memoryview(prefix)
        self.offset = 0
        self.stream = stream
    def read(self, size=-1):
        available = len(self.prefix) - self.offset
        if size is None or size < 0:
            first = self.prefix[self.offset:].tobytes()
            self.offset = len(self.prefix)
            return first + self.stream.read()
        take = min(size, available)
        first = self.prefix[self.offset:self.offset + take].tobytes()
        self.offset += take
        if take < size:
            return first + self.stream.read(size - take)
        return first

def _notify(callback, result):
    if result.suspicious and callback:
        try:
            callback({"categories": list(result.categories), "rules": [f.rule_id for f in result.findings]})
        except Exception:
            pass

class WSGIMiddleware:
    def __init__(self, app, *, inspector=None, on_detection=None, block=False, should_block=None):
        self.app, self.inspector = app, inspector or Inspector()
        self.on_detection, self.block = on_detection, bool(block)
        self.should_block = should_block or (lambda result: False)
    def __call__(self, environ, start_response):
        try:
            size = min(int(environ.get("CONTENT_LENGTH") or 0), self.inspector.max_body_bytes)
        except (TypeError, ValueError):
            size = 0
        stream = environ.get("wsgi.input")
        body = stream.read(size) if stream is not None and size else b""
        if stream is not None and size:
            environ["wsgi.input"] = _PrefixedStream(body, stream)
        headers = {k[5:].replace("_", "-"): str(v) for k, v in environ.items() if k.startswith("HTTP_")}
        req = RequestData(str(environ.get("REQUEST_METHOD", "")), str(environ.get("PATH_INFO", "")), str(environ.get("QUERY_STRING", "")), headers, body)
        result = self.inspector.inspect(req)
        _notify(self.on_detection, result)
        if self.block and result.suspicious and self.should_block(result):
            body = b'{"error":"request blocked"}'
            start_response("403 Forbidden", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
            return [body]
        return self.app(environ, start_response)

class ASGIMiddleware:
    def __init__(self, app, *, inspector=None, on_detection=None, block=False, should_block=None):
        self.app, self.inspector = app, inspector or Inspector()
        self.on_detection, self.block = on_detection, bool(block)
        self.should_block = should_block or (lambda result: False)
    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        chunks = []
        size = 0
        more = True
        while more and size < self.inspector.max_body_bytes:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            chunk = msg.get("body", b"")
            take = min(len(chunk), self.inspector.max_body_bytes - size)
            chunks.append(chunk[:take])
            size += take
            more = bool(msg.get("more_body", False))
        body = b"".join(chunks)
        replayed = False
        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()
        headers = {k.decode("latin1"): v.decode("latin1") for k, v in scope.get("headers", [])}
        req = RequestData(scope.get("method", ""), scope.get("path", ""), scope.get("query_string", b"").decode("latin1"), headers, body)
        result = self.inspector.inspect(req)
        _notify(self.on_detection, result)
        if self.block and result.suspicious and self.should_block(result):
            payload = json.dumps({"error": "request blocked"}).encode()
            await send({"type": "http.response.start", "status": 403, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]})
            await send({"type": "http.response.body", "body": payload})
            return
        await self.app(scope, replay_receive, send)

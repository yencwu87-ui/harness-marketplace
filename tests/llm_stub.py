"""A tiny local stand-in for a model API, for offline smoke tests of the kit's tracks.

It speaks just enough of two wire formats to drive one tool call and a final answer:
  POST /v1/messages          Anthropic Messages API (plain JSON, or SSE when "stream": true; count_tokens too)
  POST /v1/chat/completions  OpenAI Chat Completions API (plain JSON, or SSE when "stream": true)
  POST /v1/responses         not served (returns 404, so a client that needs it fails loudly)

Behaviour: if the conversation already holds a tool result, it answers with text that quotes the tool
result's first 200 characters. Otherwise, if tools are offered, it calls STUB_TOOL (default next_item)
with STUB_INPUT as its arguments (default: empty). Each Stub keeps the request bodies it received (`bodies`).
It binds to 127.0.0.1 only and never reaches the network.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STUB_TOOL = "next_item"
STUB_INPUT: dict = {}     # the tool input the stub asks for (tests/test_sdk_engine_smoke.py sets a Bash command)


def _anthropic_has_tool_result(body: dict) -> str | None:
    for m in body.get("messages", []):
        c = m.get("content")
        if isinstance(c, list):
            for b in c:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    cc = b.get("content")
                    if isinstance(cc, list):
                        cc = " ".join(str(x.get("text", "")) for x in cc if isinstance(x, dict))
                    return str(cc)
    return None


def _openai_has_tool_result(body: dict) -> str | None:
    for m in body.get("messages", []):
        if m.get("role") == "tool":
            c = m.get("content")
            if isinstance(c, list):
                c = " ".join(str(x.get("text", "")) for x in c if isinstance(x, dict))
            return str(c)
    return None


def _tool_names_anthropic(body):
    return [t.get("name") for t in body.get("tools", []) if isinstance(t, dict)]


def _tool_names_openai(body):
    out = []
    for t in body.get("tools", []) or []:
        f = t.get("function", t) if isinstance(t, dict) else {}
        out.append(f.get("name"))
    return out


class _Handler(BaseHTTPRequestHandler):
    server_version = "llm-stub/1"
    calls: list = []
    bodies: list = []

    def log_message(self, *a):  # quiet
        pass

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _sse(self, events):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.end_headers()
        for name, obj in events:
            line = (f"event: {name}\n" if name else "") + f"data: {obj if isinstance(obj, str) else json.dumps(obj)}\n\n"
            self.wfile.write(line.encode())
            self.wfile.flush()

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        path = self.path.split("?")[0]
        type(self).calls.append(path)
        type(self).bodies.append(body)
        if path.endswith("/messages/count_tokens"):
            return self._json(200, {"input_tokens": 10})
        if path.endswith("/v1/messages") or path.endswith("/messages"):
            return self._anthropic(body)
        if path.endswith("/chat/completions"):
            return self._openai(body)
        self._json(404, {"error": {"message": f"stub does not serve {path}"}})

    # ---------------------------------------------------------- Anthropic
    def _anthropic(self, body):
        result = _anthropic_has_tool_result(body)
        model = body.get("model", "stub")
        tools = _tool_names_anthropic(body)
        if result is None and STUB_TOOL in tools:
            block = {"type": "tool_use", "id": "toolu_stub_1", "name": STUB_TOOL, "input": dict(STUB_INPUT)}
            stop = "tool_use"
        else:
            block = {"type": "text", "text": f"Stub answer. Tool said: {(result or 'no tool')[:200]}"}
            stop = "end_turn"
        usage = {"input_tokens": 10, "output_tokens": 5}
        msg = {"id": "msg_stub", "type": "message", "role": "assistant", "model": model, "content": [block],
               "stop_reason": stop, "stop_sequence": None, "usage": usage}
        if not body.get("stream"):
            return self._json(200, msg)
        start = dict(msg, content=[], stop_reason=None)
        ev = [("message_start", {"type": "message_start", "message": start})]
        if block["type"] == "text":
            ev += [("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
                   ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": block["text"]}})]
        else:
            ev += [("content_block_start", {"type": "content_block_start", "index": 0,
                                            "content_block": {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}}),
                   ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps(STUB_INPUT)}})]
        ev += [("content_block_stop", {"type": "content_block_stop", "index": 0}),
               ("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                  "usage": {"output_tokens": 5}}),
               ("message_stop", {"type": "message_stop"})]
        self._sse(ev)

    # ---------------------------------------------------------- OpenAI
    def _openai(self, body):
        result = _openai_has_tool_result(body)
        tools = _tool_names_openai(body)
        model = body.get("model", "stub")
        if result is None and STUB_TOOL in tools:
            msg = {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_stub_1", "type": "function", "function": {"name": STUB_TOOL, "arguments": json.dumps(STUB_INPUT)}}]}
            finish = "tool_calls"
        else:
            msg = {"role": "assistant", "content": f"Stub answer. Tool said: {(result or 'no tool')[:200]}"}
            finish = "stop"
        usage = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        if not body.get("stream"):
            return self._json(200, {"id": "chatcmpl-stub", "object": "chat.completion", "created": 0, "model": model,
                                    "choices": [{"index": 0, "message": msg, "finish_reason": finish}], "usage": usage})
        base = {"id": "chatcmpl-stub", "object": "chat.completion.chunk", "created": 0, "model": model}
        if finish == "tool_calls":
            tc = msg["tool_calls"][0]
            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": tc["id"], "type": "function",
                                                          "function": {"name": tc["function"]["name"], "arguments": json.dumps(STUB_INPUT)}}]}
        else:
            delta = {"role": "assistant", "content": msg["content"]}
        ev = [(None, dict(base, choices=[{"index": 0, "delta": delta, "finish_reason": None}])),
              (None, dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": finish}], usage=usage)),
              (None, "[DONE]")]
        self._sse(ev)


class Stub:
    """with Stub() as url: ...   url is http://127.0.0.1:<port>"""

    def __enter__(self):
        self.handler = type("_StubHandler", (_Handler,), {"calls": [], "bodies": []})   # each stub its own record
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        return self

    @property
    def calls(self):
        return list(self.handler.calls)

    @property
    def bodies(self):
        return list(self.handler.bodies)

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()

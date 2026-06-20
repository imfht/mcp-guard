"""
Minimal, dependency-free MCP client for mcp-guard's "inspect" mode.

The guard acts as its own MCP client: it connects to each configured MCP server
exactly once (cached upstream), calls `tools/list` and `resources/list`, and
returns the results — including tool **descriptions** — so the guard can screen
them for poisoning. This is independent of Claude Code's in-process state.

Supported transports:
  - stdio : spawn the configured command and speak JSON-RPC over stdin/stdout.
  - http  : best-effort "Streamable HTTP" (POST JSON-RPC, parse JSON or SSE).
  - sse/ws: best-effort, same Streamable-HTTP probe (many servers accept it).

Everything here is non-fatal: a server that times out, crashes, or speaks a
dialect we don't handle is reported as `{ok: False, error: ...}` and skipped.
Only the Python standard library is used.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
import urllib.error
import urllib.request
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "mcp-guard", "version": "0.1.0"}


def _result_or_error(error: str, **extra: Any) -> dict:
    out = {"ok": False, "error": error}
    out.update(extra)
    return out


# --------------------------------------------------------------------------- #
# JSON-RPC over stdio
# --------------------------------------------------------------------------- #

class _StdioMCP:
    """Talk JSON-RPC to a stdio MCP server, one message per line."""

    def __init__(self, command: str, args: list, env: dict | None, timeout: float):
        self.timeout = timeout
        self._q: "queue.Queue[bytes | None]" = queue.Queue()
        try:
            self.proc = subprocess.Popen(
                [command, *args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,  # server logs are not our concern
                env=env,
                bufsize=0,
            )
        except FileNotFoundError:
            raise RuntimeError(f"command not found: {command}")
        except OSError as e:
            raise RuntimeError(f"failed to spawn {command}: {e}")
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        try:
            for raw in self.proc.stdout:  # type: ignore[union-attr]
                self._q.put(raw)
        except Exception:
            pass
        finally:
            self._q.put(None)

    def send(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def notification(self, method: str, params: dict | None = None) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def request(self, msg_id: int, method: str, params: dict | None = None) -> dict | None:
        """Send a request and return the matching response (skip notifications)."""
        self.send({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                raw = self._q.get(timeout=min(0.5, max(0.05, deadline - time.time())))
            except queue.Empty:
                if self.proc.poll() is not None:
                    return _result_or_error("server exited before responding")
                continue
            if raw is None:
                return _result_or_error("server closed stdout")
            line = raw.decode("utf-8", "replace").strip()
            if not line or not line.startswith("{"):
                continue  # non-JSON noise on stdout
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == msg_id:
                return msg
            # else: a notification or a different response — keep draining
        return _result_or_error("timed out waiting for response")

    def close(self) -> None:
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        except Exception:
            pass
        try:
            self.proc.stdin.close()  # type: ignore[union-attr]
        except Exception:
            pass


def _stdio_inspect(command: str, args: list, env: dict | None, timeout: float) -> dict:
    started = time.time()
    try:
        cli = _StdioMCP(command, args, env, timeout)
    except RuntimeError as e:
        return _result_or_error(str(e))

    try:
        init = cli.request(1, "initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })
        if not init or "error" in init:
            err = (init or {}).get("error") if init else "no initialize response"
            return _result_or_error(f"initialize failed: {err}")
        result = init.get("result", {})
        protocol_version = result.get("protocolVersion")
        server_info = result.get("serverInfo")

        cli.notification("notifications/initialized")

        tools_msg = cli.request(2, "tools/list", {})
        tools = []
        if tools_msg and "result" in tools_msg:
            tools = tools_msg["result"].get("tools", [])
        elif tools_msg and "error" in tools_msg:
            # tools/list is optional capability; ignore errors here
            pass

        resources_msg = cli.request(3, "resources/list", {})
        resources = []
        if resources_msg and "result" in resources_msg:
            resources = resources_msg["result"].get("resources", [])

        return {
            "ok": True,
            "transport": "stdio",
            "protocolVersion": protocol_version,
            "serverInfo": server_info,
            "tools": tools,
            "resources": resources,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    finally:
        cli.close()


# --------------------------------------------------------------------------- #
# Streamable HTTP (best-effort, also tried for sse/ws)
# --------------------------------------------------------------------------- #

def _http_request(url: str, msg: dict, headers: dict, timeout: float,
                  session_id: str | None) -> tuple[dict | None, str | None, str | None]:
    """POST one JSON-RPC message. Returns (matched_response, new_session_id, error)."""
    body = json.dumps(msg).encode("utf-8")
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    hdrs.update(headers or {})
    if session_id:
        hdrs["Mcp-Session-Id"] = session_id
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            new_sid = resp.headers.get("Mcp-Session-Id")
            ctype = resp.headers.get("Content-Type", "")
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return None, None, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, None, f"network error: {e.reason}"
    except Exception as e:
        return None, None, f"request failed: {e}"

    # Parse: either a single JSON object, or an SSE stream of "data:" lines.
    candidates: list[str] = []
    if "event-stream" in ctype or raw.lstrip().startswith("event:") or "data:" in raw:
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                candidates.append(line[5:].strip())
    else:
        candidates.append(raw.strip())

    for c in candidates:
        if not c or not c.startswith("{"):
            continue
        try:
            parsed = json.loads(c)
        except json.JSONDecodeError:
            continue
        if parsed.get("id") == msg.get("id"):
            return parsed, new_sid, None
    return None, new_sid, "no matching response in HTTP body"


def _http_inspect(url: str, headers: dict, timeout: float) -> dict:
    started = time.time()
    init_msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO,
    }}
    init, sid, err = _http_request(url, init_msg, headers, timeout, None)
    if err or not init or "error" in init:
        return _result_or_error(f"initialize failed: {err or init.get('error') if init else err}")

    result = init.get("result", {})
    protocol_version = result.get("protocolVersion")
    server_info = result.get("serverInfo")

    notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    try:
        _http_request(url, notif, headers, timeout, sid)  # fire-and-forget
    except Exception:
        pass

    tools_msg, _, _ = _http_request(
        url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        headers, timeout, sid,
    )
    tools = tools_msg.get("result", {}).get("tools", []) if tools_msg and "result" in tools_msg else []

    res_msg, _, _ = _http_request(
        url, {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
        headers, timeout, sid,
    )
    resources = res_msg.get("result", {}).get("resources", []) if res_msg and "result" in res_msg else []

    return {
        "ok": True,
        "transport": "http",
        "protocolVersion": protocol_version,
        "serverInfo": server_info,
        "tools": tools,
        "resources": resources,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def inspect_server(cfg: dict, timeout: float = 15.0) -> dict:
    """Connect to an MCP server and list its tools + resources.

    Returns a dict with at least {ok, transport} and, on success,
    {tools, resources, protocolVersion, serverInfo, elapsed_ms}. Never raises.
    """
    if not isinstance(cfg, dict):
        return _result_or_error("invalid server config")

    stype = cfg.get("type", "stdio" if "command" in cfg else "http")
    try:
        if stype == "stdio" or ("command" in cfg and stype not in ("http", "sse", "ws")):
            command = str(cfg.get("command", "")).strip()
            args = [str(a) for a in cfg.get("args", [])]
            if not command:
                return _result_or_error("stdio server has no command")
            env = dict(os.environ)
            env.update({str(k): str(v) for k, v in (cfg.get("env") or {}).items()})
            return _stdio_inspect(command, args, env, timeout)

        if stype in ("http", "sse", "ws") or "url" in cfg:
            url = str(cfg.get("url", "")).strip()
            if not url:
                return _result_or_error("remote server has no url")
            headers = {str(k): str(v) for k, v in (cfg.get("headers") or {}).items()}
            return _http_inspect(url, headers, timeout)

        return _result_or_error(f"unsupported server type: {stype!r}")
    except Exception as e:
        return _result_or_error(f"unexpected error: {e}")

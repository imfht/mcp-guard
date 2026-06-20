#!/usr/bin/env python3
"""
mcp-guard: security guard for MCP tools.

Two modes, both driven by Claude Code hooks (see ../hooks/hooks.json):

  pre-tool-use   PreToolUse hook. Reads the hook JSON from stdin, inspects the
                 MCP tool call (tool_name + tool_input) against configurable
                 suspicious patterns, logs every MCP tool call to log.jsonl,
                 and (in "block" mode) denies calls that match.

  audit          SessionStart hook. Scans MCP server configuration files on
                 disk for suspicious servers (dangerous commands, non-https /
                 raw-IP endpoints, obfuscation) and writes audit.json.

All output lives under ~/.mcp-guard/. Edit ~/.mcp-guard/config.json to tune.

No third-party dependencies — Python 3 stdlib only.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

def guard_dir() -> Path:
    """Directory where mcp-guard stores logs, audit and config."""
    d = Path(os.path.expanduser(os.environ.get("MCP_GUARD_HOME", "~/.mcp-guard")))
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_path() -> Path:
    return guard_dir() / "config.json"


def log_path() -> Path:
    return guard_dir() / "log.jsonl"


def audit_path() -> Path:
    return guard_dir() / "audit.json"


# --------------------------------------------------------------------------- #
# Config (with safe defaults; created on first run)
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG = {
    # "block"  -> deny matching tool calls via the PreToolUse hook
    # "log"    -> monitor only, never deny (safe default for first install)
    "action": "log",
    "pre_tool_use": {
        # Regex patterns tested (case-insensitive) against the tool NAME.
        "tool_name_patterns": [
            r"\b(exec|eval|system|popen|subprocess|shell_spawn|run_command|command_injection)\b",
        ],
        # Regex patterns tested against JSON.stringify(tool_input).
        "input_patterns": [
            r"\.\./",                         # path traversal
            r"/etc/(passwd|shadow|sudoers)",  # sensitive system files
            r"~/\.(ssh|aws|gnupg|config)",    # sensitive dotfiles
            r"\$\(",                           # shell command substitution
            r"`[^`]+`",                        # backtick command substitution
            r";\s*(rm|curl|wget|nc)\b",        # command chaining
            r"\|\s*(sh|bash)\b",              # pipe to shell
            r"curl[^|]*\|\s*(sh|bash)",       # curl | sh
            r"wget[^|]*\|\s*(sh|bash)",       # wget | sh
            r"base64\s+(-d|--decode)",        # base64 decode (common obfuscation)
            r"/dev/tcp/",                     # bash reverse-shell primitive
        ],
        # High-signal secret patterns. Matches are also logged as "secret_exposure".
        "secret_patterns": [
            r"AKIA[0-9A-Z]{16}",                            # AWS access key
            r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            r"gh[pousr]_[0-9A-Za-z]{36,}",                  # GitHub token
            r"xox[baprs]-[0-9A-Za-z-]{10,}",               # Slack token
        ],
        # Exact tool names (mcp__server__tool) to always allow, overriding patterns.
        "allow_tools": [],
    },
    "audit": {
        # Substrings that flag a stdio server command as suspicious.
        "suspicious_commands": [
            "curl", "wget", "nc ", "ncat", "bash -i", "sh -i",
            "python -c", "python3 -c", "eval ", "base64 --decode",
            "base64 -d", "/dev/tcp", "mkfifo",
        ],
        "flag_non_https": True,
        "flag_raw_ip_hosts": True,
    },
    "inspect": {
        # Act as an MCP client: connect to each configured server once and call
        # tools/list + resources/list so descriptions can be screened for poisoning.
        "enabled": True,
        # Per-server connect/list timeout in seconds.
        "timeout": 15,
        # Cache TTL in hours. A server is re-listed when its config changes (hash)
        # OR the cached entry is older than this. Set to 0 to force re-list every run.
        "cache_ttl_hours": 168,
        # Server names to skip during inspect (never spawned).
        "skip_servers": [],
        # Regex patterns (case-insensitive) tested against each tool's NAME + DESCRIPTION.
        # These target prompt-injection / poisoning of tool descriptions.
        "description_patterns": [
            r"ignore (all|previous|prior|the above|these) instructions",
            r"disregard (the |all |any )?(previous |prior )?(instructions|rules)",
            r"do not (show|tell|reveal|inform|share|disclose) (this|the user)",
            r"system prompt|system instruction",
            r"exfiltrat(e|ion)|send (this|data|the .*) to|upload (to|the)",
            r"\b(curl|wget)\b[^ ]*://",          # URLs in descriptions (possible exfil)
            r"\bexec(ute)?\b|\beval\b|subprocess|os\.system|popen",  # code-exec cues
            r"base64\s+(-d|--decode)",            # obfuscation
            r"[​‌‍﻿⁠]",  # zero-width / invisible unicode
            r"https?://[^\s\"')]+",               # any external link in a description
        ],
        # Flag descriptions longer than this many characters (possible hidden payload).
        "max_description_chars": 4000,
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (override wins)."""
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> dict:
    """Load config, creating it with defaults on first run."""
    p = config_path()
    if not p.exists():
        p.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
        return DEFAULT_CONFIG
    try:
        user = json.loads(p.read_text() or "{}")
    except Exception as e:
        log_raw({"event": "config_parse_error", "error": str(e)})
        return DEFAULT_CONFIG
    return deep_merge(DEFAULT_CONFIG, user)


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_raw(entry: dict) -> None:
    entry.setdefault("ts", now_iso())
    try:
        with log_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:  # never break the session over logging
        sys.stderr.write(f"mcp-guard: failed to write log: {e}\n")


def truncate(s: str, n: int = 2000) -> str:
    return s if len(s) <= n else s[:n] + "…[truncated]"


# --------------------------------------------------------------------------- #
# Hook input parsing
# --------------------------------------------------------------------------- #

def read_hook_input() -> dict:
    """Read and parse the hook JSON from stdin. Returns {} on failure."""
    try:
        raw = sys.stdin.read()
    except Exception:
        return {}
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# Mode: pre-tool-use
# --------------------------------------------------------------------------- #

def deny_output(reason: str) -> None:
    """Emit a PreToolUse deny decision as JSON on stdout (Claude Code reads it)."""
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"mcp-guard: {reason}",
        }
    }
    sys.stdout.write(json.dumps(out))


def cmd_pre_tool_use() -> int:
    data = read_hook_input()
    tool_name = data.get("tool_name") or ""
    tool_input = data.get("tool_input")

    # Only MCP tools are in scope (the hook matcher already filters, but be safe).
    if not tool_name.startswith("mcp__"):
        return 0

    cfg = load_config()
    ptu = cfg.get("pre_tool_use", {})
    allow = set(ptu.get("allow_tools", []))
    action = cfg.get("action", "log")

    if tool_name in allow:
        log_raw({
            "event": "tool_call",
            "tool_name": tool_name,
            "decision": "allowed",
            "reason": "allow_tools",
            "tool_input": truncate(json.dumps(tool_input, ensure_ascii=False)),
        })
        return 0

    hits: list[str] = []

    # tool name patterns
    for pat in ptu.get("tool_name_patterns", []):
        try:
            if re.search(pat, tool_name, re.IGNORECASE):
                hits.append(f"tool_name~/{pat}/")
        except re.error:
            pass

    input_str = json.dumps(tool_input, ensure_ascii=False) if tool_input is not None else ""

    # input patterns
    for pat in ptu.get("input_patterns", []):
        try:
            if re.search(pat, input_str, re.IGNORECASE):
                hits.append(f"tool_input~/{pat}/")
        except re.error:
            pass

    # secret exposure (always logged, only blocks in block mode)
    secret_hits = []
    for pat in ptu.get("secret_patterns", []):
        try:
            if re.search(pat, input_str):
                secret_hits.append(pat)
        except re.error:
            pass
    if secret_hits:
        hits.append("secret_exposure")

    blocked = bool(hits) and action == "block"

    log_raw({
        "event": "tool_call",
        "tool_name": tool_name,
        "decision": "blocked" if blocked else ("flagged" if hits else "allowed"),
        "action_mode": action,
        "reason": "; ".join(hits) if hits else None,
        "secrets": secret_hits or None,
        "tool_input": truncate(input_str),
    })

    if blocked:
        deny_output("suspicious MCP tool call matched: " + "; ".join(hits))
        # exit 0: the JSON deny decision is authoritative
    return 0


# --------------------------------------------------------------------------- #
# Mode: audit (SessionStart)
# --------------------------------------------------------------------------- #

def _find_mcp_servers(obj, found: dict, path: str = "") -> None:
    """Recursively collect every dict found under a 'mcpServers' key."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "mcpServers" and isinstance(v, dict):
                for srv_name, srv_cfg in v.items():
                    if isinstance(srv_cfg, dict):
                        found.setdefault(srv_name, []).append({
                            "source": path or k,
                            "cfg": srv_cfg,
                        })
            _find_mcp_servers(v, found, path)


def _candidate_config_files(cwd: str) -> list[Path]:
    home = Path.home()
    candidates = [
        Path(cwd) / ".mcp.json" if cwd else None,
        Path(cwd) / ".claude" / "settings.json" if cwd else None,
        Path(cwd) / ".claude" / "settings.local.json" if cwd else None,
        home / ".claude.json",
        home / ".claude" / "settings.json",
        Path("/etc/claude-code/managed-settings.json"),
        Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
    ]
    # enterprise/managed dirs (Linux)
    candidates.append(Path("/etc/claude-code/managed-settings.json"))
    seen, out = set(), []
    for c in candidates:
        if c is None:
            continue
        try:
            rp = c.resolve()
        except Exception:
            rp = c
        if rp in seen:
            continue
        seen.add(rp)
        if c.exists():
            out.append(c)
    return out


def _analyze_server(name: str, cfg: dict, audit_cfg: dict) -> list[str]:
    flags: list[str] = []
    stype = cfg.get("type", "stdio")
    suspicious_cmds = audit_cfg.get("suspicious_commands", [])

    if stype == "stdio" or "command" in cfg:
        cmd = str(cfg.get("command", ""))
        full = cmd + " " + " ".join(str(a) for a in cfg.get("args", []))
        for bad in suspicious_cmds:
            if bad in full:
                flags.append(f"suspicious_command:{bad.strip()}")
        # obfuscation heuristics
        if re.search(r"base64\b.*-d\b|\bbase64\b.*--decode\b", full, re.IGNORECASE):
            flags.append("base64_decode_in_command")
        if "&&" in full and any(b in full for b in suspicious_cmds):
            flags.append("chained_suspicious_command")

    if stype in ("http", "sse", "ws") or "url" in cfg:
        url = str(cfg.get("url", ""))
        if audit_cfg.get("flag_non_https", True) and url.startswith("http://"):
            flags.append("non_https_endpoint")
        if audit_cfg.get("flag_raw_ip_hosts", True):
            m = re.match(r"https?://([^/:]+)", url)
            if m and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", m.group(1)):
                flags.append("raw_ip_endpoint")
        if "metadata" in url or "internal" in url:
            pass  # too noisy; skip

    # very large env blocks can hint at exfil payloads
    env = cfg.get("env") or {}
    if isinstance(env, dict) and len(env) > 20:
        flags.append("large_env_block")

    return flags


def cmd_audit() -> int:
    data = read_hook_input()
    cwd = data.get("cwd") or os.getcwd()
    cfg = load_config()
    audit_cfg = cfg.get("audit", {})

    servers: dict = {}
    scanned: list[str] = []
    for f in _candidate_config_files(cwd):
        scanned.append(str(f))
        try:
            obj = json.loads(f.read_text() or "{}")
        except Exception:
            continue
        _find_mcp_servers(obj, servers, str(f))

    findings = []
    server_index = []
    for name, occurrences in servers.items():
        for occ in occurrences:
            sflags = _analyze_server(name, occ["cfg"], audit_cfg)
            server_index.append({
                "name": name,
                "source": occ["source"],
                "type": occ["cfg"].get("type", "stdio"),
                "command": occ["cfg"].get("command"),
                "url": occ["cfg"].get("url"),
                "flags": sflags,
            })
            for sf in sflags:
                findings.append({"server": name, "source": occ["source"], "flag": sf})

    report = {
        "ts": now_iso(),
        "cwd": cwd,
        "scanned_files": scanned,
        "servers_found": len(server_index),
        "findings": findings,
        "servers": server_index,
    }
    try:
        audit_path().write_text(json.dumps(report, indent=2) + "\n")
    except Exception as e:
        sys.stderr.write(f"mcp-guard: failed to write audit: {e}\n")

    log_raw({
        "event": "audit",
        "servers": len(server_index),
        "findings": len(findings),
        "flagged_servers": sorted({f["server"] for f in findings}),
    })

    # If a suspicious server is found, surface it as additionalContext so the
    # user (and model) see it. Non-blocking.
    if findings:
        flagged = sorted({f["server"] for f in findings})
        msg = (
            "mcp-guard: flagged MCP servers in your config: "
            + ", ".join(flagged)
            + ". Review ~/.mcp-guard/audit.json."
        )
        sys.stdout.write(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": msg,
            }
        }))
    return 0


# --------------------------------------------------------------------------- #
# Mode: inspect (act as MCP client; list tools/resources with caching)
# --------------------------------------------------------------------------- #

def cache_dir() -> Path:
    d = guard_dir() / "server-cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def inspect_path() -> Path:
    return guard_dir() / "inspect.json"


def _config_hash(name: str, cfg: dict) -> str:
    """Stable identity for a server config (excludes secret env *values*)."""
    import hashlib
    identity = {
        "name": name,
        "type": cfg.get("type", "stdio" if "command" in cfg else "http"),
        "command": cfg.get("command"),
        "args": cfg.get("args", []),
        "url": cfg.get("url"),
        "env_keys": sorted((cfg.get("env") or {}).keys()),
    }
    blob = json.dumps(identity, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _load_cache(chash: str, ttl_hours: float) -> dict | None:
    p = cache_dir() / f"{chash}.json"
    if not p.exists():
        return None
    try:
        entry = json.loads(p.read_text() or "{}")
    except Exception:
        return None
    listed_at = entry.get("listed_at_epoch", 0)
    if ttl_hours > 0 and (time.time() - listed_at) > ttl_hours * 3600:
        return None
    if entry.get("config_hash") != chash:
        return None
    return entry


def _save_cache(chash: str, entry: dict) -> None:
    entry = dict(entry)
    entry["config_hash"] = chash
    entry["listed_at_epoch"] = entry.get("listed_at_epoch") or time.time()
    try:
        (cache_dir() / f"{chash}.json").write_text(json.dumps(entry, ensure_ascii=False, indent=2))
    except Exception:
        pass


def _screen_tool(tool: dict, patterns: list, max_chars: int) -> list[str]:
    """Return poisoning-style flags for a tool, scanning name + description."""
    flags: list[str] = []
    name = str(tool.get("name", ""))
    desc = str(tool.get("description", "") or "")
    hay = f"{name}\n{desc}"
    for pat in patterns:
        try:
            if re.search(pat, hay, re.IGNORECASE):
                flags.append(f"description~/{pat}")
        except re.error:
            pass
    if not desc.strip():
        flags.append("empty_description")
    if len(desc) > max_chars:
        flags.append(f"long_description:{len(desc)}")
    # input schema sneaking executable content
    schema = json.dumps(tool.get("inputSchema") or {}, ensure_ascii=False)
    if re.search(r"\bexec(ute)?\b|\beval\b|subprocess|os\.system", schema, re.IGNORECASE):
        flags.append("schema_code_exec")
    return flags


def cmd_inspect() -> int:
    import mcp_client  # sibling module (scripts/ is sys.path[0])

    data = read_hook_input()
    cwd = data.get("cwd") or os.getcwd()
    cfg = load_config()
    insp = cfg.get("inspect", {})

    if not insp.get("enabled", True):
        log_raw({"event": "inspect", "status": "disabled"})
        return 0

    skip = set(insp.get("skip_servers", []))
    ttl = float(insp.get("cache_ttl_hours", 168))
    timeout = float(insp.get("timeout", 15))
    patterns = insp.get("description_patterns", [])
    max_chars = int(insp.get("max_description_chars", 4000))

    # Discover server configs from disk (same logic as audit).
    servers: dict = {}
    scanned: list[str] = []
    for f in _candidate_config_files(cwd):
        scanned.append(str(f))
        try:
            obj = json.loads(f.read_text() or "{}")
        except Exception:
            continue
        _find_mcp_servers(obj, servers, str(f))

    results = []
    findings = []
    for name, occurrences in servers.items():
        if name in skip:
            results.append({"name": name, "ok": False, "error": "skipped", "cached": False})
            continue
        cfg_for_server = occurrences[-1]["cfg"]  # last definition wins
        source = occurrences[-1]["source"]
        chash = _config_hash(name, cfg_for_server)

        cached = _load_cache(chash, ttl)
        if cached is not None:
            entry = cached
            entry["cached"] = True
        else:
            listing = mcp_client.inspect_server(cfg_for_server, timeout=timeout)
            entry = {
                "name": name,
                "source": source,
                "transport": listing.get("transport"),
                "ok": listing.get("ok", False),
                "error": listing.get("error"),
                "protocolVersion": listing.get("protocolVersion"),
                "serverInfo": listing.get("serverInfo"),
                "elapsed_ms": listing.get("elapsed_ms"),
                "tools": listing.get("tools", []),
                "resources": listing.get("resources", []),
                "cached": False,
            }
            _save_cache(chash, entry)

        # Screen tools for poisoning (works on cached OR fresh results).
        screened_tools = []
        for t in entry.get("tools", []):
            tflags = _screen_tool(t, patterns, max_chars)
            screened_tools.append({
                "name": t.get("name"),
                "description": truncate(str(t.get("description", "") or ""), 8000),
                "flags": tflags,
            })
            for tf in tflags:
                findings.append({"server": name, "tool": t.get("name"), "flag": tf})

        results.append({
            "name": name,
            "source": entry.get("source", source),
            "ok": entry.get("ok", False),
            "error": entry.get("error"),
            "cached": entry.get("cached", False),
            "transport": entry.get("transport"),
            "serverInfo": entry.get("serverInfo"),
            "elapsed_ms": entry.get("elapsed_ms"),
            "tool_count": len(entry.get("tools", [])),
            "resource_count": len(entry.get("resources", [])),
            "tools": screened_tools,
            "resources": entry.get("resources", []),
            "config_hash": chash,
        })

    report = {
        "ts": now_iso(),
        "cwd": cwd,
        "scanned_files": scanned,
        "servers_inspected": len(results),
        "findings": findings,
        "servers": results,
    }
    try:
        inspect_path().write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    except Exception as e:
        sys.stderr.write(f"mcp-guard: failed to write inspect report: {e}\n")

    log_raw({
        "event": "inspect",
        "servers": len(results),
        "cached": sum(1 for r in results if r.get("cached")),
        "fresh": sum(1 for r in results if not r.get("cached") and r.get("ok")),
        "failed": sum(1 for r in results if not r.get("ok") and r.get("error") != "skipped"),
        "findings": len(findings),
        "flagged": sorted({f["server"] for f in findings}),
    })

    # Surface poisoning findings to the user/model (non-blocking).
    if findings:
        flagged_tools = sorted({f"{f['server']}:{f['tool']}" for f in findings})
        msg = (
            "mcp-guard: possible MCP tool-description poisoning detected in: "
            + ", ".join(flagged_tools)
            + ". Review ~/.mcp-guard/inspect.json."
        )
        sys.stdout.write(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": msg,
            }
        }))
    return 0


# --------------------------------------------------------------------------- #
# Reporting: terminal + HTML
# --------------------------------------------------------------------------- #

def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text() or "{}")
    except Exception:
        return {}


def _load_log(limit: int = 200) -> list:
    out = []
    try:
        lines = log_path().read_text().splitlines()
    except Exception:
        return out
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
        if len(out) >= limit:
            break
    return list(reversed(out))


def _log_stats(logs: list) -> dict:
    stats = {"total": 0, "allowed": 0, "flagged": 0, "blocked": 0, "servers": set()}
    for e in logs:
        if e.get("event") != "tool_call":
            continue
        stats["total"] += 1
        dec = e.get("decision")
        if dec in stats:
            stats[dec] += 1
        if e.get("tool_name"):
            stats["servers"].add(e["tool_name"].split("__")[1] if e["tool_name"].startswith("mcp__") else e["tool_name"])
    stats["servers"] = sorted(stats["servers"])
    return stats


def cmd_report() -> int:
    """Pretty-print a terminal summary of all collected data."""
    insp = _load_json(inspect_path())
    aud = _load_json(audit_path())
    logs = _load_log()
    stats = _log_stats(logs)
    cfg = load_config()
    bold = "\033[1m"; red = "\033[31m"; yel = "\033[33m"; grn = "\033[32m"; dim = "\033[2m"; rst = "\033[0m"
    if not sys.stdout.isatty():
        bold = red = yel = grn = dim = rst = ""

    print(f"\n{bold}mcp-guard report{rst} {dim}· {now_iso()}{rst}")
    print(f"  action mode: {bold}{cfg.get('action')}{rst}")

    # findings (poisoning)
    findings = insp.get("findings", [])
    head = red + "⚠ " if findings else grn
    print(f"\n{bold}{head}Description-poisoning findings: {len(findings)}{rst}")
    flagged_tools = {}
    for f in findings:
        flagged_tools.setdefault(f"{f['server']}:{f['tool']}", []).append(f["flag"])
    for k, flags in flagged_tools.items():
        print(f"  {red}{k}{rst}")
        for fl in flags:
            print(f"      · {fl}")

    # servers (from inspect)
    print(f"\n{bold}MCP servers (live tools/list):{rst}")
    if not insp.get("servers"):
        print(f"  {dim}(no inspect data yet — start a session to list servers){rst}")
    for s in insp.get("servers", []):
        status = grn + "ok" + rst if s.get("ok") else red + (s.get("error") or "failed") + rst
        cached = "cached" if s.get("cached") else "fresh"
        print(f"  · {bold}{s['name']}{rst} [{status}] {dim}{s.get('transport')} · {s.get('tool_count',0)} tools · {cached}{rst}")
        for t in s.get("tools", []):
            mark = red + "✗" if t.get("flags") else grn + "·"
            desc = (t.get("description") or "").replace("\n", " ")[:80]
            print(f"      {mark} {t['name']}{rst} {dim}{desc}{rst}")

    # audit
    aud_findings = aud.get("findings", [])
    print(f"\n{bold}Config audit findings: {len(aud_findings)}{rst}")
    for f in aud_findings:
        print(f"  {yel}{f['server']}{rst}: {f['flag']}")

    # activity
    print(f"\n{bold}Tool-call activity (recent):{rst}")
    print(f"  total={stats['total']} allowed={grn}{stats['allowed']}{rst} "
          f"flagged={yel}{stats['flagged']}{rst} blocked={red}{stats['blocked']}{rst}")
    for e in logs[:10]:
        if e.get("event") == "tool_call":
            c = red if e.get("decision") == "blocked" else (yel if e.get("decision") == "flagged" else dim)
            print(f"  {c}{e.get('decision'):8}{rst} {e.get('tool_name')} {dim}{e.get('ts','')[11:19]}{rst}")
    print()
    return 0


def _esc(s) -> str:
    import html as _html
    return _html.escape("" if s is None else str(s))


def cmd_html() -> int:
    """Write a self-contained HTML report and print its path."""
    insp = _load_json(inspect_path())
    aud = _load_json(audit_path())
    logs = _load_log(100)
    stats = _log_stats(logs)
    cfg = load_config()

    findings = insp.get("findings", [])
    flagged = {}
    for f in findings:
        flagged.setdefault(f"{f['server']}:{f['tool']}", []).append(f["flag"])

    def tool_rows(tools):
        rows = []
        for t in tools:
            flags = t.get("flags") or []
            cls = ' class="bad"' if flags else ""
            desc = (t.get("description") or "<i>no description</i>")
            fl = "".join(f"<span class='flag'>{_esc(x)}</span>" for x in flags)
            rows.append(
                f"<tr{cls}><td><code>{_esc(t.get('name'))}</code></td>"
                f"<td>{_esc(desc) if t.get('description') else desc}<br>{fl}</td></tr>"
            )
        return "".join(rows)

    server_cards = []
    for s in insp.get("servers", []):
        ok = s.get("ok")
        badge = '<span class="badge ok">connected</span>' if ok else f'<span class="badge bad">{_esc(s.get("error") or "failed")}</span>'
        server_cards.append(f"""
        <div class="card">
          <h3>{_esc(s['name'])} {badge}</h3>
          <div class="meta">{_esc(s.get('transport'))} · {_esc(s.get('tool_count',0))} tools · {_esc(s.get('resource_count',0))} resources · {'cached' if s.get('cached') else 'fresh'} · {_esc(s.get('elapsed_ms'))}ms</div>
          <table><thead><tr><th>Tool</th><th>Description</th></tr></thead><tbody>{tool_rows(s.get('tools', []))}</tbody></table>
        </div>""")

    aud_rows = "".join(
        f"<tr><td><code>{_esc(f.get('server'))}</code></td><td>{_esc(f.get('source'))}</td><td>{_esc(f.get('flag'))}</td></tr>"
        for f in aud.get("findings", [])
    ) or '<tr><td colspan="3" class="muted">none</td></tr>'

    log_rows = "".join(
        f"<tr class=\"{e.get('decision','')}\"><td>{_esc(e.get('ts','')[11:19])}</td>"
        f"<td><code>{_esc(e.get('tool_name'))}</code></td><td>{_esc(e.get('decision'))}</td>"
        f"<td>{_esc(e.get('reason'))}</td></tr>"
        for e in logs if e.get("event") == "tool_call"
    ) or '<tr><td colspan="4" class="muted">no MCP tool calls yet</td></tr>'

    banner = ""
    if flagged:
        items = "".join(f"<li><code>{_esc(k)}</code> — {', '.join(_esc(x) for x in v)}</li>" for k, v in flagged.items())
        banner = f'<div class="banner"><b>⚠ {len(flagged)} tool(s) with suspicious descriptions</b><ul>{items}</ul></div>'

    html_doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>mcp-guard report</title><style>
 body{{font-family:-apple-system,system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9;padding:24px}}
 h1{{color:#58a6ff}} h3{{margin:0 0 8px}}
 .sub{{color:#8b949e;margin-top:-8px}}
 .banner{{background:#3d1f1f;border:1px solid #f85149;border-radius:8px;padding:14px 18px;margin:18px 0}}
 .banner ul{{margin:6px 0 0}} .banner code{{background:#21152a;padding:1px 5px;border-radius:4px}}
 .card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin:14px 0}}
 table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}}
 td,th{{text-align:left;padding:6px 8px;border-bottom:1px solid #21262d;vertical-align:top}}
 th{{color:#8b949e;font-weight:600}} .muted{{color:#6e7681}}
 tr.bad td{{background:#2a1414}} code{{background:#21262d;padding:1px 5px;border-radius:4px;color:#79c0ff}}
 .flag{{display:inline-block;background:#3d1f1f;color:#f85149;border:1px solid #6f2622;border-radius:4px;padding:0 6px;margin:2px 4px 0 0;font-size:11px}}
 .badge{{font-size:11px;padding:2px 8px;border-radius:10px;margin-left:6px}} .ok{{background:#1a3a28;color:#3fb950}} .bad{{background:#3d1f1f;color:#f85149}}
 .meta{{color:#8b949e;font-size:12px;margin-bottom:6px}}
 tr.blocked td{{color:#f85149}} tr.flagged td{{color:#d29922}}
 .grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:14px 0}}
 .stat{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px;text-align:center}}
 .stat b{{display:block;font-size:26px}} .stat span{{color:#8b949e;font-size:12px}}
</style></head><body>
<h1>🛡 mcp-guard report</h1>
<div class="sub">generated {now_iso()} · action mode: <b>{_esc(cfg.get('action'))}</b></div>
{banner}
<div class="grid">
 <div class="stat"><b>{len(insp.get('servers',[]))}</b><span>MCP servers</span></div>
 <div class="stat"><b>{sum(len(s.get('tools',[])) for s in insp.get('servers',[]))}</b><span>tools listed</span></div>
 <div class="stat"><b style="color:#f85149">{len(flagged)}</b><span>poisoning findings</span></div>
</div>
<h2>🔎 MCP servers &amp; tool descriptions</h2>
{''.join(server_cards) or '<p class="muted">No inspect data yet. Start a Claude Code session in a project with MCP servers configured, then refresh.</p>'}
<h2>🔍 Config audit (on disk)</h2>
<table><thead><tr><th>Server</th><th>Source</th><th>Flag</th></tr></thead><tbody>{aud_rows}</tbody></table>
<h2>📝 Recent MCP tool calls</h2>
<div class="grid">
 <div class="stat"><b>{stats['total']}</b><span>total</span></div>
 <div class="stat"><b style="color:#3fb950">{stats['allowed']}</b><span>allowed</span></div>
 <div class="stat"><b style="color:#d29922">{stats['flagged']}</b><span>flagged</span></div>
 <div class="stat"><b style="color:#f85149">{stats['blocked']}</b><span>blocked</span></div>
</div>
<table><thead><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Reason</th></tr></thead><tbody>{log_rows}</tbody></table>
</body></html>"""

    out = guard_dir() / "report.html"
    out.write_text(html_doc, encoding="utf-8")
    print(str(out))
    # best-effort open in browser
    import shutil, subprocess
    opener = {"linux": "xdg-open", "darwin": "open", "win32": "start"}.get(__import__("sys").platform)
    if opener and shutil.which(opener == "start" and "cmd" or opener):
        try:
            subprocess.Popen([opener, str(out)] if opener != "start" else ["cmd", "/c", "start", "", str(out)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    return 0


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    if not argv:
        sys.stderr.write("usage: mcp_guard.py <pre-tool-use|audit|inspect|report|html>\n")
        return 2
    mode = argv[0]
    if mode == "pre-tool-use":
        return cmd_pre_tool_use()
    if mode == "audit":
        return cmd_audit()
    if mode == "inspect":
        return cmd_inspect()
    if mode == "report":
        return cmd_report()
    if mode == "html":
        return cmd_html()
    sys.stderr.write(f"mcp_guard.py: unknown mode {mode!r}\n")
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as e:
        # Hooks must never crash the session. Log and allow.
        sys.stderr.write(f"mcp-guard: internal error: {e}\n")
        sys.exit(0)

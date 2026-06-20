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
# Entry point
# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    if not argv:
        sys.stderr.write("usage: mcp_guard.py <pre-tool-use|audit>\n")
        return 2
    mode = argv[0]
    if mode == "pre-tool-use":
        return cmd_pre_tool_use()
    if mode == "audit":
        return cmd_audit()
    sys.stderr.write(f"mcp_guard.py: unknown mode {mode!r}\n")
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as e:
        # Hooks must never crash the session. Log and allow.
        sys.stderr.write(f"mcp-guard: internal error: {e}\n")
        sys.exit(0)

# mcp-guard

A security guard **plugin for [Claude Code](https://docs.claude.com/en/docs/claude-code)** that watches the Model Context Protocol (MCP) surface for tool/prompt poisoning.

It does three things, all from **stock installable hooks** (no source patching, no rebuild):

1. **Logs every MCP tool call** to `~/.mcp-guard/log.jsonl` — server, tool name, input, and the decision.
2. **Audits MCP server configs on disk** at session start and writes `~/.mcp-guard/audit.json` — flagging suspicious commands, non-HTTPS endpoints, raw-IP hosts, and obfuscation.
3. **Blocks** MCP tool calls that match configurable suspicious patterns (path traversal, shell injection, `curl|sh`, leaked secrets, …) — opt-in, off by default.

Use `/mcp-guard:report` in a session to get a Markdown summary of everything above.

---

## Install

### From the marketplace (recommended)

```
/plugin marketplace add imfht/mcp-guard
/plugin install mcp-guard@mcp-guard
```

Then restart the session. The `SessionStart` audit will run automatically on the next launch.

### Try it without installing (session only)

```
claude --plugin-dir /path/to/clone/of/mcp-guard
```

---

## How it works

`hooks/hooks.json` declares two Claude Code hooks that the plugin ships:

| Hook | Mode | What it does |
|------|------|--------------|
| `PreToolUse` (`mcp__.*`) | `pre-tool-use` | Inspects each MCP tool call's name + input, logs it, and (in block mode) denies matches. |
| `SessionStart` (`startup\|resume`) | `audit` | Scans MCP config files on disk and reports suspicious servers. |

Both hooks are plain `command` (shell) hooks that run `scripts/mcp_guard.py` (Python 3 stdlib only — no dependencies). The hook payload (tool name, input, cwd, …) arrives on stdin as JSON, exactly as Claude Code sends it.

### Files written

| Path | Contents |
|------|----------|
| `~/.mcp-guard/config.json` | Tunable config (created on first run with defaults). |
| `~/.mcp-guard/log.jsonl`   | One line per MCP tool call: `decision` = `allowed` / `flagged` / `blocked`. |
| `~/.mcp-guard/audit.json`  | Latest config audit: servers found, findings, files scanned. |

---

## Configuration

Edit `~/.mcp-guard/config.json`. Key fields:

```jsonc
{
  // "log" = monitor only (default). "block" = deny matching tool calls.
  "action": "log",
  "pre_tool_use": {
    "tool_name_patterns": ["\\b(exec|eval|system|subprocess|shell_spawn|...)\\b"],
    "input_patterns":     ["\\.\\./", "/etc/passwd", "\\$\\(", "curl[^|]*\\|\\s*(sh|bash)", ...],
    "secret_patterns":    ["AKIA[0-9A-Z]{16}", "-----BEGIN ... PRIVATE KEY-----", "ghp_...", ...],
    "allow_tools":        []   // exact mcp__server__tool names to always allow
  },
  "audit": {
    "suspicious_commands": ["curl", "wget", "nc ", "bash -i", "python -c", "base64 -d", ...],
    "flag_non_https": true,
    "flag_raw_ip_hosts": true
  }
}
```

**Monitor first, then enforce.** The default `action` is `"log"` so installing the plugin never disrupts legitimate tools. Once you've reviewed `log.jsonl` and tuned `allow_tools`, flip `action` to `"block"`.

Set `MCP_GUARD_HOME=/some/dir` to relocate all outputs (handy for testing).

---

## What this plugin can and cannot detect

This is a **stock plugin**, and Claude Code's plugin hooks can only run as external processes (shell/HTTP/prompt) — they receive the *hook payload* (tool name + input, and the on-disk config), **not** the in-memory `AppState`. That means:

✅ **Can detect**
- Suspicious MCP tool *calls*: dangerous tool names, path traversal, command injection, `curl|sh`, exposed secrets in arguments.
- Suspicious MCP server *configurations*: dangerous stdio commands, non-HTTPS / raw-IP endpoints, obfuscation, oversized env blocks.
- Full audit trail of every MCP tool invocation.

❌ **Cannot detect (without a source patch)**
- A tool's *description* / *schema* being poisoned — descriptions live in-memory in `AppState.mcp.tools` and are **not** passed to external hook processes. A stock plugin simply cannot see them. If you need to enumerate every MCP tool's name + description at runtime (e.g. to spot a tool whose description contains hidden injection instructions), that requires registering an **in-process `callback` hook** that reads `context.getAppState().mcp.tools` — which only works inside a source-patched / self-built Claude Code. See [`docs/in-process-poc.md`](docs/in-process-poc.md) for that technique and a working POC.

In short: this plugin catches **behavior** (what tools do and how they're configured). Catching **description poisoning** requires the in-process approach documented separately.

---

## Development / testing

```
# Unit-test the script modes against a throwaway home
MCP_GUARD_HOME=/tmp/mg python3 scripts/mcp_guard.py audit <<'EOF'
{"cwd":"/path/to/project","source":"startup"}
EOF

# End-to-end with stock claude-code + a demo MCP server
claude --plugin-dir . --mcp-config path/to/config.json -p "..."
```

Requires Python 3.6+.

---

## License

MIT © imfht

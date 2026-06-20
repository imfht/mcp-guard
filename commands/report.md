---
description: Summarize mcp-guard security findings (logged MCP tool calls + config audit)
allowed-tools: Read, Bash, Grep
---

Read the mcp-guard logs and produce a concise security report.

Steps:
1. Read `~/.mcp-guard/audit.json` and summarize: how many MCP servers were found, which were flagged and why, and which config files were scanned.
2. Read `~/.mcp-guard/log.jsonl` (use Grep/Read; it can be large). Tally the `decision` field: how many `allowed`, `flagged`, and `blocked` MCP tool calls. List every `blocked` and `flagged` call with its `tool_name`, `reason`, and timestamp.
3. If a `~/.mcp-guard/config.json` exists, note the current `action` mode (`log` vs `block`) and remind the user how to switch.
4. Call out any `secret_exposure` hits specifically — these are high priority.

Output a short Markdown report with sections: **Audit summary**, **Tool-call activity**, **High-priority findings**, and **Recommendations**. Do not modify any files.

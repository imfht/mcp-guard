# Node-layer hook (preload shim)

A third technique for capturing MCP tool **descriptions** — alongside the stock
plugin's self-MCP-client `inspect` and the in-process `callback` hook.

**Idea:** instead of re-listing each server ourselves (the stock plugin's
`inspect`) or reading `AppState` (the in-process POC), we patch the JS runtime
builtins that Claude Code uses to talk to MCP servers, and **tee the
`tools/list` responses as Claude Code itself fetches them**. Zero extra spawns.

See [`scripts/node-hook-shim.js`](../scripts/node-hook-shim.js) for the working,
verified shim.

## Feasibility (empirically tested)

| Claude Code form | Node-layer hook feasible? | Why |
|------------------|---------------------------|-----|
| **Stock compiled binary** (`claude`, the shipped ELF) | ❌ **No** | Sealed. `BUN_PRELOAD`, `NODE_OPTIONS=--require`, and `--inspect` are all ignored/rejected. |
| **Self-built** (`bun dist/cli.js` or from source) | ✅ **Yes** | `bun --preload ./scripts/node-hook-shim.js dist/cli.js …` fires the shim and captures descriptions. |

> So this technique needs a self-built Claude Code — same requirement as the
> in-process POC. It does **not** work for users running the stock binary (use
> the stock plugin's `inspect` mode for that).

## Why it works against the bundled `dist/cli.js`

Bun bundles app code and npm deps into one file, but **runtime builtins are
never inlined** — `node:child_process` and `globalThis.fetch` are always the
process's own. A `--preload` shim that mutates those before the bundle runs
affects every call the bundle makes, including its MCP transports.

- **stdio servers**: wrap `child_process.spawn`, tee each child's stdout, parse
  newline-delimited JSON-RPC, capture `result.tools` / `result.resources`.
- **http/sse servers**: wrap `globalThis.fetch`, read the response body (JSON or
  SSE `data:` lines), capture the same.

## Verified output

```
$ bun --preload ./scripts/node-hook-shim.js dist/cli.js --mcp-config cfg.json -p "..."
$ cat /tmp/node-hook/captures.jsonl
{"transport":"stdio","cmd":"bun .../poc-server.ts","count":2,
 "items":[{"name":"echo","description":"Echoes back the provided message..."},
          {"name":"get_time","description":"Returns the current ISO timestamp..."}]}
```

Both demo tools + descriptions captured from Claude Code's **own** spawn — no
second process was started.

## How it compares

| | Stock plugin `inspect` | In-process `callback` | **Node-layer preload shim** |
|---|---|---|---|
| Works on stock binary | ✅ | ❌ | ❌ |
| Needs self-built Claude Code | no | yes | **yes** |
| Extra spawns | one per server (cached) | none | **none** |
| OAuth servers | ❌ (can't connect) | ✅ | **✅** |
| Captures descriptions | ✅ (re-lists) | ✅ (from AppState) | **✅** (from the wire) |
| Fragility | server config / protocol | React store internals | builtin API surface (fairly stable) |
| Install | `/plugin install` | patch source + rebuild | `--preload` flag, no rebuild |

This is the cleanest capture (wire-level, zero overhead) **if** you're already
running a self-built Claude Code. For everyone else, the stock plugin's
`inspect` remains the zero-install answer.

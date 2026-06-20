# In-process POC: enumerating MCP tool *descriptions*

> **Update:** the stock plugin now screens tool **descriptions** without any of
> this — its `inspect` mode acts as its own MCP client and calls `tools/list` on
> each server directly (see the README). This in-process technique remains useful
> for two cases the client-side `inspect` can't cover: (1) servers Claude Code has
> already authenticated via OAuth (the guard can't reuse that session), and
> (2) reading live `AppState` (connection state, capabilities) rather than
> re-listing. For plain description poisoning detection, use `inspect`.

This plugin (`mcp-guard`) deliberately stays a **stock** installable plugin, which
means it can only see the *hook payload* (tool name + input, on-disk config) —
plus whatever it can fetch itself as an MCP client. It **cannot** read a tool's
description/schema from Claude Code's in-memory `AppState.mcp.tools`, because that
is never serialized to an external hook process.

This document shows the technique that *can* reach the in-memory state:
registering an **in-process `callback` hook** inside a self-built / source-patched
Claude Code. It is included for completeness and for anyone doing deep
MCP-poisoning research. **You do not need this to use the stock plugin.**

## Why a stock plugin can't do this

Claude Code's persisted hook schema (`HookCommandSchema`) allows only four types:
`command` (shell), `prompt`, `agent`, `http`. The in-process `callback` type
(`HookCallback` in `src/types/hooks.ts`) is a pure TypeScript construct that is
**never** parseable from JSON and is only reachable via the internal
`registerHookCallbacks(...)` API. A `callback` hook receives a `context` whose
`getAppState()` returns the live `AppState`, including `mcp.tools`.

## The POC

Register a `PreToolUse` callback that reads every MCP tool's name + description
and dumps them to a file. Wire the registration into `setup.ts` (next to
`registerSessionFileAccessHooks()`), then build with `bun run build.ts`.

```ts
// src/utils/mcpInspector.ts
import { registerHookCallbacks } from '../bootstrap/state.js'
import { writeFileSync, mkdirSync, existsSync } from 'fs'

const OUTPUT_FILE = '/tmp/mcp-poc-output/tools.json'

async function exportMcpTools(appState: any, triggerTool: string | null = null) {
  const tools = appState.mcp?.tools || []
  const clients = appState.mcp?.clients || []
  const out: any[] = []
  for (const tool of tools) {
    if (!tool.name?.startsWith('mcp__')) continue
    let description = ''
    try {
      description = await tool.description({}, {
        isNonInteractiveSession: false,
        toolPermissionContext: appState.toolPermissionContext,
        tools,
      })
    } catch (e) { description = `Error: ${e}` }
    const client = clients.find((c: any) => c.name === tool.mcpInfo?.serverName)
    out.push({
      name: tool.name,
      description,
      mcpInfo: tool.mcpInfo,
      serverInfo: { name: tool.mcpInfo?.serverName, type: client?.type, configType: client?.config?.type },
      hasInputSchema: !!tool.inputJSONSchema,
    })
  }
  if (!existsSync('/tmp/mcp-poc-output')) mkdirSync('/tmp/mcp-poc-output', { recursive: true })
  writeFileSync(OUTPUT_FILE, JSON.stringify({ triggerTool, totalMcpTools: out.length, tools: out }, null, 2))
}

export function registerMcpInspectorHooks() {
  registerHookCallbacks({
    PreToolUse: [{
      matcher: '*',
      hooks: [{
        type: 'callback',
        callback: async (_input, _id, _sig, _i, context) => {
          if (!context) return {}
          const appState = context.getAppState()
          await exportMcpTools(appState, _input?.tool_name ?? null)
          // To DENY a suspicious tool, return:
          //   return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: '...' } }
          return {}
        },
        timeout: 10,
      }],
    }],
  })
}
```

```ts
// src/setup.ts  (add next to the other registerXxxHooks() call)
void import('./utils/mcpInspector.js').then(m => m.registerMcpInspectorHooks())
```

Then build and run against a demo MCP server:

```bash
bun run build.ts                          # defines the MACRO/feature macros
bun dist/cli.js --mcp-config cfg.json -p "call mcp__demo__echo"
cat /tmp/mcp-poc-output/tools.json        # names + descriptions + live connection state
```

## Verified output (excerpt)

```json
{
  "totalMcpTools": 2,
  "tools": [
    {
      "name": "mcp__poc-demo__echo",
      "description": "Echoes back the provided message. ...",
      "mcpInfo": { "serverName": "poc-demo", "toolName": "echo" },
      "serverInfo": { "name": "poc-demo", "type": "connected", "configType": "stdio" },
      "hasInputSchema": true
    }
  ]
}
```

Note the `"type": "connected"` — that field is only knowable from the in-memory
runtime, which is the proof that the callback is reading live `AppState`, not
config files. A poisoned description (e.g. hidden instructions inside
`description`) would be visible here and could be denied by returning a
`permissionDecision: "deny"` from the callback.

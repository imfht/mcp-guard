// Reference: Node/Bun runtime-layer hook for MCP tool descriptions.
//
// Run with a SELF-BUILT Claude Code (the stock compiled binary ignores
// BUN_PRELOAD / NODE_OPTIONS / --inspect — it is sealed):
//
//   bun --preload ./scripts/node-hook-shim.js dist/cli.js --mcp-config cfg.json -p "..."
//
// What it does: patches the `node:child_process` builtin (NOT inlined by the
// bundler, so the patch affects the bundle) so every spawned stdio MCP server
// has its stdout tee'd — capturing the JSON-RPC `tools/list` / `resources/list`
// responses as Claude Code itself fetches them. Also patches `globalThis.fetch`
// for http/sse transports. Result: tool descriptions are captured with ZERO
// extra spawns, including OAuth-authenticated servers (it's Claude Code's own
// client). Captures land in /tmp/node-hook/.
//
// Verified: captures both demo tools (echo, get_time) + descriptions from a
// `bun --preload ... dist/cli.js` run.

import { mkdirSync, writeFileSync, appendFileSync } from 'node:fs'
import { createRequire } from 'node:module'

const OUT = '/tmp/node-hook'
mkdirSync(OUT, { recursive: true })
writeFileSync(`${OUT}/fired`, `shim loaded ${new Date().toISOString()}`)

function record(kind, cmd, result) {
  try {
    appendFileSync(`${OUT}/captures.jsonl`, JSON.stringify({
      ts: new Date().toISOString(), transport: kind, cmd,
      count: (result.tools || result.resources || []).length,
      items: (result.tools || result.resources || []).map(t => ({
        name: t.name, description: (t.description || '').slice(0, 200),
      })),
    }) + '\n')
  } catch {}
}

// ---- stdio: wrap child_process.spawn ----
const require = createRequire(import.meta.url)
const cp = require('node:child_process')
const origSpawn = cp.spawn
cp.spawn = function () {
  const child = origSpawn.apply(this, arguments)
  try {
    const cmdStr = arguments[1] && Array.isArray(arguments[1])
      ? `${arguments[0]} ${arguments[1].join(' ')}`
      : String(arguments[0])
    if (child?.stdout && !child.stdout.__mcpHooked) {
      child.stdout.__mcpHooked = true
      let buf = ''
      child.stdout.on('data', d => {
        buf += d.toString()
        let i
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i); buf = buf.slice(i + 1)
          try {
            const m = JSON.parse(line)
            if (m?.result?.tools) record('stdio', cmdStr, m.result)
            if (m?.result?.resources) record('stdio', cmdStr, m.result)
          } catch {}
        }
      })
    }
  } catch {}
  return child
}

// ---- http/sse: wrap global fetch ----
const origFetch = globalThis.fetch
globalThis.fetch = async function (url, opts = {}) {
  const res = await origFetch.apply(this, arguments)
  try {
    const ct = res.headers.get('content-type') || ''
    const clone = res.clone()
    const body = await clone.text()
    const probe = body.split('\n').map(l => l.replace(/^data:\s*/, '').trim()).filter(l => l.startsWith('{'))
    for (const line of probe.slice(0, 8)) {
      try {
        const m = JSON.parse(line)
        if (m?.result?.tools) record('http', String(url), m.result)
        if (m?.result?.resources) record('http', String(url), m.result)
      } catch {}
    }
  } catch {}
  return res
}

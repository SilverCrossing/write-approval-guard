import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { apply } from '../index.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-gate-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })
const systemRoot = path.join(base, 'fakesys')
fs.mkdirSync(systemRoot, { recursive: true })

function harness(options = {}) {
  const roots = Array.isArray(options.roots) ? options.roots : []
  const listeners = new Map()
  const ctx = {
    get(name) {
      if (name === 'commands') return { register: () => () => {} }
      if (name === 'workingDirectory') return { ensure: async () => workspace }
      if (name === 'agents') return { roots: () => roots.map(id => ({ id })) }
      return undefined
    },
    on(event, handler) {
      listeners.set(event, handler)
      return () => listeners.delete(event)
    },
    effect(callback) {
      const dispose = callback()
      return () => {
        if (typeof dispose === 'function') dispose()
      }
    },
  }
  return { ctx, listeners }
}

function run(listeners, name, args) {
  return listeners.get('tools/pre-execute')(
    {
      name,
      arguments: args,
      agent: { id: 'agent-test' },
      signal: new AbortController().signal,
      callId: 'call-1',
    },
    async () => ({ kind: 'allow' }),
  )
}

test('gateWrites all (default) still asks for an ordinary write', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, {})
  const result = await run(listeners, 'write', { file_path: path.join(workspace, 'a.txt'), content: 'x' })
  assert.equal(result.kind, 'ask')
})

test('gateWrites risky lets an ordinary write through', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'risky' })
  const result = await run(listeners, 'write', { file_path: path.join(workspace, 'a.txt'), content: 'x' })
  assert.equal(result.kind, 'allow')
})

test('gateWrites risky still stops a sensitive write (now a config write)', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'risky' })
  const result = await run(listeners, 'write', { file_path: path.join(workspace, '.env'), content: 'A=1' })
  // No approval service here, so the high-risk path fails closed.
  assert.equal(result.kind, 'deny')
})

test('gateWrites risky still asks for a sensitive read', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'risky' })
  const result = await run(listeners, 'read', { file_path: path.join(workspace, '.env') })
  assert.equal(result.kind, 'ask')
})

test('gateWrites risky lets an ordinary shell write through', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'risky' })
  const result = await run(listeners, 'pwsh', { command: 'Set-Content .\\notes.txt hi' })
  assert.equal(result.kind, 'allow')
})

test('gateWrites risky still stops a destructive command', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'risky' })
  const result = await run(listeners, 'pwsh', { command: 'Remove-Item -Recurse -Force .\\build' })
  assert.equal(result.kind, 'deny')
})

test('gateWrites risky still stops a system-path write', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'risky', extraSystemRoots: [systemRoot] })
  const result = await run(listeners, 'write', { file_path: path.join(systemRoot, 'x.txt'), content: 'x' })
  assert.equal(result.kind, 'deny')
})

test('gateWrites workspace lets an ordinary write inside the workspace through', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'workspace' })
  const result = await run(listeners, 'write', { file_path: path.join(workspace, 'a.txt'), content: 'x' })
  assert.equal(result.kind, 'allow')
})

test('gateWrites workspace still asks outside the workspace', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'workspace' })
  const result = await run(listeners, 'write', { file_path: path.join(base, 'outside.txt'), content: 'x' })
  assert.equal(result.kind, 'ask')
})

test('gateWrites workspace keeps protected in-workspace paths gated', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'workspace' })
  const target = path.join(workspace, 'node_modules', '.bin', 'tool.cmd')
  const result = await run(listeners, 'write', { file_path: target, content: 'x' })
  assert.equal(result.kind, 'ask')
})

test('gateWrites workspace still asks for shell writes', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'workspace' })
  const result = await run(listeners, 'pwsh', { command: 'Set-Content .\\notes.txt hi' })
  assert.equal(result.kind, 'ask')
})

test('gateWrites workspace asks when one target of a multi-file call is outside', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'workspace' })
  const result = await run(listeners, 'multi_edit', {
    edits: [
      { file: path.join(workspace, 'a.txt'), old: 'a', new: 'b' },
      { file: path.join(base, 'outside.txt'), old: 'a', new: 'b' },
    ],
  })
  assert.equal(result.kind, 'ask')
})

test('a subagent can write in the workspace while the main session still asks', async () => {
  const { ctx, listeners } = harness({ roots: ['root-session'] })
  apply(ctx, { gateWrites: 'all', subagentGateWrites: 'workspace' })
  const result = await run(listeners, 'write', { file_path: path.join(workspace, 'a.txt'), content: 'x' })
  assert.equal(result.kind, 'allow')
})

test('the top-level session keeps its own gate policy', async () => {
  const { ctx, listeners } = harness({ roots: ['agent-test'] })
  apply(ctx, { gateWrites: 'all', subagentGateWrites: 'workspace' })
  const result = await run(listeners, 'write', { file_path: path.join(workspace, 'a.txt'), content: 'x' })
  assert.equal(result.kind, 'ask')
})

test('subagentGateWrites unset inherits gateWrites', async () => {
  const { ctx, listeners } = harness({ roots: ['root-session'] })
  apply(ctx, { gateWrites: 'all' })
  const result = await run(listeners, 'write', { file_path: path.join(workspace, 'a.txt'), content: 'x' })
  assert.equal(result.kind, 'ask')
})

test('a subagent workspace policy still asks for shell writes', async () => {
  const { ctx, listeners } = harness({ roots: ['root-session'] })
  apply(ctx, { gateWrites: 'all', subagentGateWrites: 'workspace' })
  const result = await run(listeners, 'pwsh', { command: 'Set-Content .\\notes.txt hi' })
  assert.equal(result.kind, 'ask')
})

test('a subagent risky policy also frees shell writes (documented risk)', async () => {
  const { ctx, listeners } = harness({ roots: ['root-session'] })
  apply(ctx, { gateWrites: 'all', subagentGateWrites: 'risky' })
  const result = await run(listeners, 'pwsh', { command: 'Set-Content .\\notes.txt hi' })
  assert.equal(result.kind, 'allow')
})

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

function harness() {
  const listeners = new Map()
  const ctx = {
    get(name) {
      if (name === 'commands') return { register: () => () => {} }
      if (name === 'workingDirectory') return { ensure: async () => workspace }
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

test('gateWrites risky still asks for a sensitive write', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, { gateWrites: 'risky' })
  const result = await run(listeners, 'write', { file_path: path.join(workspace, '.env'), content: 'A=1' })
  assert.equal(result.kind, 'ask')
  assert.match(result.displayReason.zh, /敏感文件/)
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

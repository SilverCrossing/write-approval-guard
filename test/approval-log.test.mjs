import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { apply } from '../index.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-approval-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })

function harness() {
  const listeners = new Map()
  const ctx = {
    get(name) {
      if (name === 'workingDirectory') return { ensure: async () => workspace }
      if (name === 'commands') return { register: () => () => {} }
      return undefined
    },
    on(event, handler) {
      if (!listeners.has(event)) listeners.set(event, [])
      listeners.get(event).push(handler)
      return () => {}
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

function listenerOf(listeners, event) {
  const list = listeners.get(event) ?? []
  assert.ok(list.length > 0, `no listener for ${event}`)
  return list[0]
}

function logLines(dir) {
  if (!fs.existsSync(dir)) return []
  return fs
    .readdirSync(dir)
    .flatMap(name => fs.readFileSync(path.join(dir, name), 'utf8').trim().split('\n'))
    .filter(Boolean)
    .map(line => JSON.parse(line))
}

test('logs the approval outcome for a call this plugin gated', async () => {
  const logDir = path.join(base, 'logs')
  const { ctx, listeners } = harness()
  apply(ctx, { logDir })

  const pre = listenerOf(listeners, 'tools/pre-execute')
  const decision = await pre(
    {
      name: 'write',
      arguments: { file_path: path.join(workspace, 'a.txt'), content: 'x' },
      agent: { id: 'agent-1' },
      callId: 'call-1',
      signal: new AbortController().signal,
    },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(decision.kind, 'ask')

  const approval = listenerOf(listeners, 'approval/request')
  const outcome = await approval(
    { callId: 'call-1', toolName: 'write', agent: { id: 'agent-1' }, reason: 'x' },
    async () => 'rejected',
  )
  assert.equal(outcome, 'rejected')

  const line = logLines(logDir).find(entry => entry.event === 'approval')
  assert.ok(line)
  assert.equal(line.outcome, 'rejected')
  assert.equal(line.tool, 'write')
  assert.equal(line.kind, 'write')
})

test('does not log approvals this plugin never asked for', async () => {
  const logDir = path.join(base, 'logs-unrelated')
  const { ctx, listeners } = harness()
  apply(ctx, { logDir })

  const approval = listenerOf(listeners, 'approval/request')
  await approval({ callId: 'other-call', toolName: 'read' }, async () => 'allowed-once')

  assert.equal(logLines(logDir).filter(entry => entry.event === 'approval').length, 0)
})

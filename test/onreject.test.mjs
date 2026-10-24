import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { apply } from '../index.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-onreject-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })

function harness({ approval, agent } = {}) {
  const listeners = new Map()
  const commands = { register: () => () => {} }
  const ctx = {
    get(name) {
      if (name === 'commands') return commands
      if (name === 'workingDirectory') return { ensure: async () => workspace }
      if (name === 'approval') return approval
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
  return { ctx, listeners, commands }
}

function execution(name, args, agent) {
  return {
    name,
    arguments: args,
    agent,
    signal: new AbortController().signal,
    callId: 'call-1',
  }
}

function fakeAgent() {
  let cancels = 0
  return {
    id: 'agent-test',
    cancel() {
      cancels += 1
    },
    cancels() {
      return cancels
    },
  }
}

const allowedApproval = () => {
  const calls = []
  return {
    calls,
    async request(request) {
      calls.push(request)
      return 'allowed-once'
    },
  }
}

const rejectingApproval = () => {
  const calls = []
  return {
    calls,
    async request(request) {
      calls.push(request)
      return 'rejected'
    },
  }
}

test('onReject defaults to call: a rejection does not cancel the turn', async () => {
  const approval = rejectingApproval()
  const agent = fakeAgent()
  const { ctx, listeners } = harness({ approval })
  apply(ctx, {})

  const handler = listeners.get('tools/pre-execute')
  const result = await handler(
    execution('write', { file_path: path.join(workspace, 'a.txt'), content: 'x\n' }, agent),
    async () => ({ kind: 'allow' }),
  )

  // In `call` mode the plugin delegates the ordinary approval to the runtime,
  // so it never sees the rejection and never cancels the turn.
  assert.equal(result.kind, 'ask')
  assert.equal(approval.calls.length, 0)
  assert.equal(agent.cancels(), 0)
})

test('onReject call still delegates to the runtime ask', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, {})
  const handler = listeners.get('tools/pre-execute')
  const result = await handler(
    execution('write', { file_path: path.join(workspace, 'b.txt'), content: 'x\n' }, fakeAgent()),
    async () => ({ kind: 'allow' }),
  )
  assert.equal(result.kind, 'ask')
})

test('onReject turn cancels the turn and says so', async () => {
  const approval = rejectingApproval()
  const agent = fakeAgent()
  const { ctx, listeners } = harness({ approval })
  apply(ctx, { onReject: 'turn' })

  const handler = listeners.get('tools/pre-execute')
  const result = await handler(
    execution('write', { file_path: path.join(workspace, 'c.txt'), content: 'x\n' }, agent),
    async () => ({ kind: 'allow' }),
  )

  assert.equal(approval.calls.length, 1)
  assert.equal(agent.cancels(), 1)
  assert.equal(result.kind, 'deny')
  assert.match(result.reason, /stopped the current turn/)
  assert.match(result.info.reason, /停止了本轮/)
})

test('onReject turn approves through the plugin and continues', async () => {
  const approval = allowedApproval()
  const agent = fakeAgent()
  const { ctx, listeners } = harness({ approval })
  apply(ctx, { onReject: 'turn' })

  const handler = listeners.get('tools/pre-execute')
  const result = await handler(
    execution('write', { file_path: path.join(workspace, 'd.txt'), content: 'x\n' }, agent),
    async () => ({ kind: 'allow' }),
  )

  assert.equal(result.kind, 'allow')
  assert.equal(approval.calls.length, 1)
  assert.equal(agent.cancels(), 0)
})

test('onReject turn stops the turn when the first high-risk confirmation is rejected', async () => {
  const approval = rejectingApproval()
  const agent = fakeAgent()
  const { ctx, listeners } = harness({ approval })
  apply(ctx, { onReject: 'turn' })

  const handler = listeners.get('tools/pre-execute')
  const result = await handler(
    execution('pwsh', { command: 'Remove-Item -Recurse -Force .\\build' }, agent),
    async () => ({ kind: 'allow' }),
  )

  assert.equal(agent.cancels(), 1)
  assert.equal(result.kind, 'deny')
  assert.match(approval.calls[0].displayReason.zh, /第 1\/2 次确认/)
  assert.match(approval.calls[0].reason, /confirmation 1\/2/)
})

test('onReject turn maps a cancelled approval to a cancellation', async () => {
  const approval = { async request() { return 'cancelled' } }
  const agent = fakeAgent()
  const { ctx, listeners } = harness({ approval })
  apply(ctx, { onReject: 'turn' })

  const handler = listeners.get('tools/pre-execute')
  const result = await handler(
    execution('write', { file_path: path.join(workspace, 'e.txt'), content: 'x\n' }, agent),
    async () => ({ kind: 'allow' }),
  )

  assert.equal(result.kind, 'cancel')
  assert.equal(agent.cancels(), 0)
})

test('onReject turn without an approval service denies instead of executing', async () => {
  const agent = fakeAgent()
  const { ctx, listeners } = harness()
  apply(ctx, { onReject: 'turn' })

  const handler = listeners.get('tools/pre-execute')
  const result = await handler(
    execution('write', { file_path: path.join(workspace, 'f.txt'), content: 'x\n' }, agent),
    async () => ({ kind: 'allow' }),
  )

  assert.equal(result.kind, 'deny')
  assert.match(result.reason, /approval-unavailable/)
  assert.equal(agent.cancels(), 0)
})

test('onReject turn falls back to a plain rejection without agent.cancel', async () => {
  const approval = rejectingApproval()
  const agent = { id: 'agent-no-cancel' }
  const { ctx, listeners } = harness({ approval })
  apply(ctx, { onReject: 'turn' })

  const handler = listeners.get('tools/pre-execute')
  const result = await handler(
    execution('write', { file_path: path.join(workspace, 'g.txt'), content: 'x\n' }, agent),
    async () => ({ kind: 'allow' }),
  )

  assert.equal(result.kind, 'deny')
  assert.doesNotMatch(result.reason, /stopped the current turn/)
})

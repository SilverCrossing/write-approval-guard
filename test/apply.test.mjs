import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { apply } from '../index.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-apply-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })
fs.writeFileSync(path.join(workspace, 'inside.txt'), 'inside')
fs.writeFileSync(path.join(workspace, '.env'), 'TOKEN=1')

function commandRegistry() {
  const byName = new Map()
  return {
    register(definition) {
      byName.set(definition.name, definition)
      return () => byName.delete(definition.name)
    },
    get(name) {
      return byName.get(name)
    },
    names() {
      return [...byName.keys()]
    },
  }
}

function harness({ commands = commandRegistry(), approval } = {}) {
  const listeners = new Map()
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

async function preExecute(listeners, execution) {
  const handler = listeners.get('tools/pre-execute')
  assert.equal(typeof handler, 'function')
  return handler(execution, async () => ({ kind: 'allow' }))
}

const signal = new AbortController().signal
const agent = { id: 'agent-test' }

function exec(name, args) {
  return { name, arguments: args, agent, signal, callId: 'call-1' }
}

test('apply registers /write-guard with a status report', async () => {
  const { ctx, commands } = harness()
  apply(ctx, {})
  assert.deepEqual(commands.names(), ['write-guard'])

  const status = await commands.get('write-guard').handler({ rawInput: 'status' })
  assert.equal(status.kind, 'success')
  assert.match(status.text, /写操作审批：启用/)
})

test('a write inside the workspace returns ask', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, {})
  const result = await preExecute(listeners, exec('write', { file_path: path.join(workspace, 'new.txt') }))
  assert.equal(result.kind, 'ask')
  assert.match(result.displayReason.zh, /写操作需要审批/)
})

test('an ordinary read is delegated to next()', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, {})
  const result = await preExecute(listeners, exec('read', { file_path: path.join(workspace, 'inside.txt') }))
  assert.equal(result.kind, 'allow')
})

test('reading .env returns ask', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, {})
  const result = await preExecute(listeners, exec('read', { file_path: path.join(workspace, '.env') }))
  assert.equal(result.kind, 'ask')
  assert.match(result.displayReason.zh, /读取敏感文件/)
})

test('a plain write does not call the approval service itself', async () => {
  const calls = []
  const approval = {
    async request(request) {
      calls.push(request)
      return 'allowed-once'
    },
  }
  const { ctx, listeners } = harness({ approval })
  apply(ctx, {})
  const result = await preExecute(listeners, exec('write', { file_path: path.join(workspace, 'new.txt') }))
  assert.equal(result.kind, 'ask')
  assert.equal(calls.length, 0)
})

test('a high-risk call asks twice and denies when step 1 is rejected', async () => {
  const calls = []
  const approval = {
    async request(request) {
      calls.push(request)
      return 'rejected'
    },
  }
  const { ctx, listeners } = harness({ approval })
  apply(ctx, {})
  const result = await preExecute(listeners, exec('pwsh', { command: 'Remove-Item -Recurse -Force .\\build' }))
  assert.equal(calls.length, 1)
  assert.match(calls[0].displayReason.zh, /第 1\/2 次确认/)
  assert.equal(result.kind, 'deny')
})

test('a high-risk call falls through to the ordinary approval when step 1 passes', async () => {
  const calls = []
  const approval = {
    async request(request) {
      calls.push(request)
      return 'allowed-once'
    },
  }
  const { ctx, listeners } = harness({ approval })
  apply(ctx, {})
  const result = await preExecute(listeners, exec('pwsh', { command: 'rm -rf ./build' }))
  assert.equal(calls.length, 1)
  assert.equal(result.kind, 'ask')
  assert.match(result.displayReason.zh, /第 2\/2 次确认/)
})

test('cancelling step 1 cancels the call', async () => {
  const approval = { async request() { return 'cancelled' } }
  const { ctx, listeners } = harness({ approval })
  apply(ctx, {})
  const result = await preExecute(listeners, exec('pwsh', { command: 'format C:' }))
  assert.equal(result.kind, 'cancel')
})

test('a missing approval service denies the high-risk call', async () => {
  const { ctx, listeners } = harness()
  apply(ctx, {})
  const result = await preExecute(listeners, exec('pwsh', { command: 'diskpart' }))
  assert.equal(result.kind, 'deny')
  assert.match(result.reason, /approval-unavailable/)
})

test('highRiskConfirmations single skips the first dialog', async () => {
  const calls = []
  const approval = {
    async request(request) {
      calls.push(request)
      return 'allowed-once'
    },
  }
  const { ctx, listeners } = harness({ approval })
  apply(ctx, { highRiskConfirmations: 'single' })
  const result = await preExecute(listeners, exec('pwsh', { command: 'rm -rf ./build' }))
  assert.equal(calls.length, 0)
  assert.equal(result.kind, 'ask')
  assert.doesNotMatch(result.displayReason.zh, /第 2\/2 次确认/)
})

test('sensitiveReadConfirmations double confirms a .env read twice', async () => {
  const calls = []
  const approval = {
    async request(request) {
      calls.push(request)
      return 'allowed-once'
    },
  }
  const { ctx, listeners } = harness({ approval })
  apply(ctx, { sensitiveReadConfirmations: 'double' })
  const result = await preExecute(listeners, exec('read', { file_path: path.join(workspace, '.env') }))
  assert.equal(calls.length, 1)
  assert.equal(result.kind, 'ask')
  assert.match(result.displayReason.zh, /第 2\/2 次确认/)
})

test('/write-guard off disables the gate until restart', async () => {
  const { ctx, listeners, commands } = harness()
  apply(ctx, {})
  const off = await commands.get('write-guard').handler({ rawInput: 'off' })
  assert.equal(off.kind, 'success')

  const result = await preExecute(listeners, exec('write', { file_path: path.join(workspace, 'new.txt') }))
  assert.equal(result.kind, 'allow')
})

test('an invalid command argument is rejected', async () => {
  const { ctx, commands } = harness()
  apply(ctx, {})
  const result = await commands.get('write-guard').handler({ rawInput: 'nonsense' })
  assert.equal(result.kind, 'error')
})

test('a missing commands service does not break the gate', async () => {
  const { ctx, listeners } = harness({ commands: undefined })
  apply(ctx, {})
  const result = await preExecute(listeners, exec('write', { file_path: path.join(workspace, 'new.txt') }))
  assert.equal(result.kind, 'ask')
})

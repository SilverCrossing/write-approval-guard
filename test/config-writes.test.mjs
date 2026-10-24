import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { classifyToolCall } from '../classify.js'
import { apply } from '../index.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-config-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })
const cwd = workspace

function call(name, args, config = {}) {
  return classifyToolCall({ name, args, cwd, config })
}

test('shell startup scripts are high risk', () => {
  const decision = call('write', { file_path: path.join(workspace, '.bashrc'), content: 'x' })
  assert.equal(decision.kind, 'config-write')
  assert.equal(decision.risk, 'high')
})

test('git hooks are high risk', () => {
  const decision = call('safe_write', {
    filepath: path.join(workspace, '.git', 'hooks', 'pre-commit'),
    content: 'x',
  })
  assert.equal(decision.kind, 'config-write')
})

test('editor task files are high risk', () => {
  const decision = call('write', { file_path: path.join(workspace, '.vscode', 'tasks.json'), content: '{}' })
  assert.equal(decision.kind, 'config-write')
})

test('agent instruction files are high risk', () => {
  assert.equal(call('write', { file_path: path.join(workspace, 'AGENTS.md'), content: 'x' }).risk, 'high')
  const prompt = call('write', { file_path: path.join(workspace, '.dsh-prompts', 'guardrails.md'), content: 'x' })
  assert.equal(prompt.kind, 'config-write')
})

test('env and package-manager configuration is high risk', () => {
  assert.equal(call('write', { file_path: path.join(workspace, '.env'), content: 'x' }).kind, 'config-write')
  assert.equal(call('write', { file_path: path.join(workspace, '.npmrc'), content: 'x' }).kind, 'config-write')
})

test('shell commands writing a profile or env file are high risk', () => {
  assert.equal(call('pwsh', { command: 'Set-Content $PROFILE -Value "x"' }).kind, 'config-write')
  assert.equal(call('pwsh', { command: 'echo x > .bashrc' }).kind, 'config-write')
})

test('ordinary files and ordinary shell writes are unaffected', () => {
  assert.equal(call('write', { file_path: path.join(workspace, 'notes.txt'), content: 'x' }).kind, 'write')
  assert.equal(call('pwsh', { command: 'Set-Content .\\notes.txt hi' }).kind, 'shell-write')
})

test('application config directories and *.config files are high risk', () => {
  const dotConfig = call('write', { file_path: path.join(workspace, '.config'), content: 'x' })
  assert.equal(dotConfig.kind, 'config-write')
  const nested = call('write', {
    file_path: path.join(base, 'home', '.config', 'app', 'settings.json'),
    content: '{}',
  })
  assert.equal(nested.kind, 'config-write')
  const dotNet = call('write', { file_path: path.join(workspace, 'web.config'), content: '<configuration/>' })
  assert.equal(dotNet.kind, 'config-write')
  assert.equal(call('pwsh', { command: 'Set-Content .config -Value x' }).kind, 'config-write')
})

test('gateWrites risky still stops configuration writes', async () => {
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
  apply(ctx, { gateWrites: 'risky' })
  const result = await listeners.get('tools/pre-execute')(
    {
      name: 'write',
      arguments: { file_path: path.join(workspace, '.bashrc'), content: 'x' },
      agent: { id: 'agent-test' },
      signal: new AbortController().signal,
      callId: 'call-1',
    },
    async () => ({ kind: 'allow' }),
  )
  // This harness has no approval service, so the high-risk path fails closed.
  assert.equal(result.kind, 'deny')
})

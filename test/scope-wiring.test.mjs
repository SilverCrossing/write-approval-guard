import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { apply } from '../index.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-scope-'))
const docs = path.join(base, 'docs')
const code = path.join(base, 'code')
fs.mkdirSync(docs, { recursive: true })
fs.mkdirSync(code, { recursive: true })

const mainA = { id: 'a', session: { id: 's1' } }
const mainB = { id: 'b', session: { id: 's2' } }
const child = { id: 'c', session: { id: 's3' } }

function harness({ dirs, roots }) {
  const listeners = new Map()
  const commands = new Map()
  const ctx = {
    get(name) {
      if (name === 'commands') {
        return {
          register(definition) {
            commands.set(definition.name, definition)
            return () => commands.delete(definition.name)
          },
        }
      }
      if (name === 'workingDirectory') return { ensure: async agent => dirs.get(agent.id) ?? null }
      if (name === 'agents') return { roots: () => roots }
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

function preExecute(listeners, execution) {
  return listeners.get('tools/pre-execute')(execution, async () => ({ kind: 'allow' }))
}

function exec(agent, name, args) {
  return { name, arguments: args, agent, signal: new AbortController().signal, callId: `call-${agent.id}` }
}

test('a session override never leaks into another session', async () => {
  const dirs = new Map([['a', docs], ['b', docs], ['c', docs]])
  const h = harness({ dirs, roots: [mainA, mainB] })
  apply(h.ctx, {})
  await h.commands.get('write-guard').handler({ rawInput: 'workspace', agent: mainA })

  const scoped = await preExecute(h.listeners, exec(mainA, 'write', { file_path: path.join(docs, 'a.txt') }))
  assert.equal(scoped.kind, 'allow')

  const other = await preExecute(h.listeners, exec(mainB, 'write', { file_path: path.join(docs, 'b.txt') }))
  assert.equal(other.kind, 'ask')
})

test('a workspace binding applies without any command', async () => {
  const dirs = new Map([['a', docs], ['b', code]])
  const h = harness({ dirs, roots: [mainA, mainB] })
  apply(h.ctx, { workspaces: [{ root: docs, mode: 'workspace' }] })

  const bound = await preExecute(h.listeners, exec(mainA, 'write', { file_path: path.join(docs, 'x.txt') }))
  assert.equal(bound.kind, 'allow')

  const unbound = await preExecute(h.listeners, exec(mainB, 'write', { file_path: path.join(code, 'x.txt') }))
  assert.equal(unbound.kind, 'ask')
})

test('a session override outranks the workspace binding', async () => {
  const dirs = new Map([['a', docs]])
  const h = harness({ dirs, roots: [mainA] })
  apply(h.ctx, { workspaces: [{ root: docs, mode: 'workspace' }] })
  await h.commands.get('write-guard').handler({ rawInput: 'all', agent: mainA })
  const result = await preExecute(h.listeners, exec(mainA, 'write', { file_path: path.join(docs, 'x.txt') }))
  assert.equal(result.kind, 'ask')
})

test('reset returns to the workspace binding', async () => {
  const dirs = new Map([['a', docs]])
  const h = harness({ dirs, roots: [mainA] })
  apply(h.ctx, { workspaces: [{ root: docs, mode: 'workspace' }] })
  const command = h.commands.get('write-guard')
  await command.handler({ rawInput: 'all', agent: mainA })
  const reset = await command.handler({ rawInput: 'reset', agent: mainA })
  assert.match(reset.text, /工作区绑定/)

  const result = await preExecute(h.listeners, exec(mainA, 'write', { file_path: path.join(docs, 'x.txt') }))
  assert.equal(result.kind, 'allow')
})

test('a subagent does not inherit the session override', async () => {
  const dirs = new Map([['a', docs], ['c', docs]])
  const h = harness({ dirs, roots: [mainA] })
  apply(h.ctx, {})
  await h.commands.get('write-guard').handler({ rawInput: 'workspace', agent: mainA })
  const result = await preExecute(h.listeners, exec(child, 'write', { file_path: path.join(docs, 'x.txt') }))
  assert.equal(result.kind, 'ask')
})

test('status reports where the effective policy came from', async () => {
  const dirs = new Map([['a', docs]])
  const h = harness({ dirs, roots: [mainA] })
  apply(h.ctx, {})
  const command = h.commands.get('write-guard')

  const base = await command.handler({ rawInput: 'status', agent: mainA })
  assert.match(base.text, /来源：配置默认/)

  await command.handler({ rawInput: 'risky', agent: mainA })
  const scoped = await command.handler({ rawInput: 'status', agent: mainA })
  assert.match(scoped.text, /来源：本会话覆盖/)
})

import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { classifyToolCall } from '../classify.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-unknown-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })
const cwd = workspace

function call(name, args, config = {}) {
  return classifyToolCall({ name, args, cwd, config })
}

test('an unrecognized tool is allowed by default', () => {
  assert.equal(call('foo_write', { target: path.join(workspace, 'a.txt') }), null)
})

test('unknownTools ask gates an unrecognized tool', () => {
  const decision = call('foo_write', { target: path.join(workspace, 'a.txt') }, { unknownTools: 'ask' })
  assert.ok(decision)
  assert.equal(decision.kind, 'unknown-tool')
  assert.match(decision.displayReason.zh, /未登记的工具需要审批/)
})

test('unknownTools ask still gates read-only tools that are known here', () => {
  assert.equal(call('read', { file_path: path.join(workspace, 'a.txt') }, { unknownTools: 'ask' }), null)
  assert.equal(call('syntax_check', { filepath: path.join(workspace, 'a.py') }, { unknownTools: 'ask' }), null)
})

test('unknownTools ask keeps the normal verdict for covered tools', () => {
  const decision = call(
    'safe_write',
    { filepath: path.join(workspace, 'a.txt'), content: 'x' },
    { unknownTools: 'ask' },
  )
  assert.equal(decision.kind, 'write')
})

test('unknownTools ask skips ignored tools', () => {
  assert.equal(
    call('web_search', { queries: ['x'] }, { unknownTools: 'ask', ignoreTools: ['web_search'] }),
    null,
  )
})

test('unknownTools ask shows the noise cost for unrelated tools', () => {
  const decision = call('web_search', { queries: ['x'] }, { unknownTools: 'ask' })
  assert.equal(decision.kind, 'unknown-tool')
})

test('unknownTools allow keeps unrelated tools quiet', () => {
  assert.equal(call('web_search', { queries: ['x'] }), null)
})

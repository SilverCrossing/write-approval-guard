import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { classifyToolCall } from '../classify.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-toolkit-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })
const cwd = workspace

function call(name, args, config = {}) {
  return classifyToolCall({ name, args, cwd, config })
}

test('safe_write replaces write and asks', () => {
  const decision = call('safe_write', { filepath: path.join(workspace, 'a.txt'), content: 'x' })
  assert.ok(decision)
  assert.equal(decision.kind, 'write')
  assert.match(decision.displayReason.zh, /写操作需要审批/)
})

test('safe_edit replaces edit and asks', () => {
  const decision = call('safe_edit', { filepath: path.join(workspace, 'a.txt'), old: 'x', new: 'y' })
  assert.equal(decision.kind, 'write')
})

test('safe_rollback writes the file back and asks', () => {
  const decision = call('safe_rollback', { filepath: path.join(workspace, 'a.txt') })
  assert.equal(decision.kind, 'write')
})

test('multi_edit asks and reports how many files the call touches', () => {
  const decision = call('multi_edit', {
    edits: [
      { file: path.join(workspace, 'a.ts'), old: 'a', new: 'b' },
      { file: path.join(workspace, 'b.ts'), old: 'c', new: 'd' },
    ],
  })
  assert.equal(decision.kind, 'write')
  assert.match(decision.displayReason.zh, /本次共 2 个文件/)
})

test('multi_edit keeps the strongest verdict across its files', () => {
  const systemRoot = path.join(base, 'fakesys')
  fs.mkdirSync(systemRoot, { recursive: true })
  const decision = call(
    'multi_edit',
    {
      edits: [
        { file: path.join(workspace, 'a.ts'), old: 'a', new: 'b' },
        { file: path.join(systemRoot, 'b.ts'), old: 'c', new: 'd' },
      ],
    },
    { extraSystemRoots: [systemRoot] },
  )
  assert.equal(decision.kind, 'system-write')
  assert.equal(decision.risk, 'high')
})

test('multi_edit flags a sensitive target', () => {
  const decision = call('multi_edit', {
    edits: [{ file: path.join(workspace, '.env'), old: 'A=1', new: 'A=2' }],
  })
  assert.equal(decision.kind, 'sensitive-write')
})

test('safe_write to a system path is high risk', () => {
  const systemRoot = path.join(base, 'fakesys2')
  fs.mkdirSync(systemRoot, { recursive: true })
  const decision = call(
    'safe_write',
    { filepath: path.join(systemRoot, 'x.txt'), content: 'x' },
    { extraSystemRoots: [systemRoot] },
  )
  assert.equal(decision.kind, 'system-write')
  assert.equal(decision.risk, 'high')
})

test('test_runner is treated as running project code', () => {
  const decision = call('test_runner', { framework: 'auto' })
  assert.equal(decision.kind, 'shell-write')
  assert.match(decision.displayReason.zh, /运行项目代码/)
})

test('test_runner follows the shell gate', () => {
  assert.equal(call('test_runner', { framework: 'auto' }, { gateShell: false }), null)
  assert.equal(call('test_runner', { framework: 'auto' }, { shellMode: 'off' }), null)
})

test('syntax_check and safe_backups are not gated', () => {
  assert.equal(call('syntax_check', { filepath: path.join(workspace, 'a.py') }), null)
  assert.equal(call('safe_backups', { filepath: path.join(workspace, 'a.py') }), null)
})

test('the native tools still behave as before', () => {
  assert.equal(call('write', { file_path: path.join(workspace, 'n.txt'), content: 'x' }).kind, 'write')
  assert.equal(call('read', { file_path: path.join(workspace, 'n.txt') }), null)
})

test('exempt paths still skip safe_write', () => {
  const scratch = path.join(workspace, 'scratch')
  fs.mkdirSync(scratch, { recursive: true })
  assert.equal(
    call('safe_write', { filepath: path.join(scratch, 'x.txt'), content: 'x' }, { exemptPaths: [scratch] }),
    null,
  )
})

test('safe_rollback says it overwrites and names the snapshot', () => {
  const decision = call('safe_rollback', { filepath: path.join(workspace, 'a.txt') })
  assert.match(decision.displayReason.zh, /回滚会覆盖当前内容/)
  assert.match(decision.displayReason.zh, /最近一次改动前快照/)
})

test('safe_rollback shows a named snapshot', () => {
  const decision = call('safe_rollback', {
    filepath: path.join(workspace, 'a.txt'),
    backup_name: '20260101T000000000Z~edit.bak',
  })
  assert.match(decision.displayReason.zh, /20260101T000000000Z~edit\.bak/)
})

test('safe_rollback keeps the high-risk warning for system paths', () => {
  const systemRoot = path.join(base, 'fakesys3')
  fs.mkdirSync(systemRoot, { recursive: true })
  const decision = call(
    'safe_rollback',
    { filepath: path.join(systemRoot, 'x.txt') },
    { extraSystemRoots: [systemRoot] },
  )
  assert.equal(decision.risk, 'high')
  assert.match(decision.displayReason.zh, /^高危：/)
  assert.match(decision.displayReason.zh, /回滚会覆盖当前内容/)
})

import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { classifyShell, classifyToolCall, matchSensitive } from '../classify.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-test-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })
fs.writeFileSync(path.join(workspace, 'notes.txt'), 'hello')

const cwd = workspace

function call(name, args, config = {}) {
  return classifyToolCall({ name, args, cwd, config })
}

test('write inside the workspace still asks', () => {
  const decision = call('write', { file_path: path.join(workspace, 'a.txt') })
  assert.ok(decision)
  assert.equal(decision.risk, 'normal')
  assert.equal(decision.kind, 'write')
  assert.match(decision.displayReason.zh, /写操作需要审批/)
})

test('edit inside the workspace asks', () => {
  const decision = call('edit', { file_path: path.join(workspace, 'notes.txt') })
  assert.equal(decision.kind, 'write')
})

test('reading an ordinary file is not gated', () => {
  assert.equal(call('read', { file_path: path.join(workspace, 'notes.txt') }), null)
})

test('reading .env asks', () => {
  const decision = call('read', { file_path: path.join(workspace, '.env') })
  assert.ok(decision)
  assert.equal(decision.kind, 'sensitive-read')
  assert.match(decision.displayReason.zh, /读取敏感文件/)
})

test('reading .env.local asks', () => {
  assert.equal(call('read', { file_path: path.join(workspace, '.env.local') }).kind, 'sensitive-read')
})

test('reading inside a .config directory asks', () => {
  const target = path.join(workspace, '.config', 'app', 'settings.json')
  assert.equal(call('read', { file_path: target }).kind, 'sensitive-read')
})

test('reading a private key asks', () => {
  assert.equal(call('read', { file_path: path.join(workspace, 'id_rsa') }).kind, 'sensitive-read')
})

test('writing a sensitive file asks once (not high risk)', () => {
  const decision = call('write', { file_path: path.join(workspace, '.env') })
  assert.equal(decision.kind, 'sensitive-write')
  assert.equal(decision.risk, 'normal')
})

test('grep with a sensitive include pattern asks', () => {
  const decision = call('grep', { pattern: 'TOKEN', path: workspace, include: '*.env' })
  assert.equal(decision.kind, 'sensitive-read')
})

test('grep inside a sensitive directory asks', () => {
  const decision = call('grep', { pattern: 'x', path: path.join(workspace, '.ssh') })
  assert.equal(decision.kind, 'sensitive-read')
})

test('glob over an ordinary directory is not gated', () => {
  assert.equal(call('glob', { pattern: '**/*.txt', path: workspace }), null)
})

test('writing into a configured system root is high risk', () => {
  const systemRoot = path.join(base, 'fakesys')
  fs.mkdirSync(systemRoot, { recursive: true })
  const decision = call(
    'write',
    { file_path: path.join(systemRoot, 'x.txt') },
    { extraSystemRoots: [systemRoot] },
  )
  assert.equal(decision.kind, 'system-write')
  assert.equal(decision.risk, 'high')
})

test('exempt paths skip the write approval but not system paths', () => {
  const scratch = path.join(workspace, 'scratch')
  fs.mkdirSync(scratch, { recursive: true })
  assert.equal(
    call('write', { file_path: path.join(scratch, 'x.txt') }, { exemptPaths: [scratch] }),
    null,
  )
})

test('ignored tools are not inspected', () => {
  assert.equal(
    call('write', { file_path: path.join(workspace, '.env') }, { ignoreTools: ['write'] }),
    null,
  )
})

test('sensitiveReadConfirmations double raises the risk', () => {
  const decision = call(
    'read',
    { file_path: path.join(workspace, '.env') },
    { sensitiveReadConfirmations: 'double' },
  )
  assert.equal(decision.risk, 'high')
})

test('a read-only shell command is not gated', () => {
  assert.equal(call('pwsh', { command: 'git status' }), null)
  assert.equal(call('pwsh', { command: 'Get-Content .\\notes.txt' }), null)
  assert.equal(call('pwsh', { command: 'git status 2>&1' }), null)
})

test('an unknown shell command asks in conservative mode', () => {
  const decision = call('pwsh', { command: 'node scripts/build.mjs' })
  assert.equal(decision.kind, 'shell-write')
})

test('an unknown shell command is allowed in lenient mode', () => {
  assert.equal(call('pwsh', { command: 'node scripts/build.mjs' }, { shellMode: 'lenient' }), null)
})

test('writing through a shell command asks', () => {
  assert.equal(call('pwsh', { command: 'Set-Content .\\notes.txt hi' }).kind, 'shell-write')
  assert.equal(call('pwsh', { command: 'echo hi > out.txt' }).kind, 'shell-write')
})

test('recursive deletes are high risk', () => {
  const decision = call('pwsh', { command: 'Remove-Item -Recurse -Force .\\build' })
  assert.equal(decision.kind, 'destructive')
  assert.equal(decision.risk, 'high')
  assert.equal(call('bash', { command: 'rm -rf ./build' }).risk, 'high')
  assert.equal(call('pwsh', { command: 'rd /s /q D:\\old' }).risk, 'high')
})

test('disk and format commands are high risk', () => {
  assert.equal(call('pwsh', { command: 'format C: /fs:NTFS' }).risk, 'high')
  assert.equal(call('pwsh', { command: 'diskpart /s script.txt' }).risk, 'high')
})

test('system configuration commands are high risk', () => {
  assert.equal(call('pwsh', { command: 'reg add HKLM\\Software\\x /v y /d z' }).risk, 'high')
  assert.equal(call('pwsh', { command: 'bcdedit /set {default} safeboot minimal' }).risk, 'high')
  assert.equal(call('pwsh', { command: 'netsh advfirewall set allprofiles state off' }).risk, 'high')
})

test('permission changes are high risk', () => {
  assert.equal(call('pwsh', { command: 'icacls C:\\data /reset' }).risk, 'high')
  assert.equal(call('bash', { command: 'chmod -R 777 /srv' }).risk, 'high')
})

test('writing a system file through a shell command is high risk', () => {
  if (process.platform !== 'win32') return
  const decision = call('pwsh', { command: 'Set-Content C:\\Windows\\System32\\drivers\\etc\\hosts x' })
  assert.equal(decision.kind, 'system-write')
  assert.equal(decision.risk, 'high')
})

test('reading a sensitive file through a shell command asks', () => {
  assert.equal(call('pwsh', { command: 'Get-Content .env' }).kind, 'sensitive-read')
  assert.equal(call('bash', { command: 'cat ~/.ssh/id_rsa' }).kind, 'sensitive-read')
})

test('git writes are plain approvals, not high risk', () => {
  const decision = call('pwsh', { command: 'git clean -xdf' })
  assert.equal(decision.risk, 'normal')
  assert.equal(decision.kind, 'shell-write')
  assert.equal(call('pwsh', { command: 'git status' }), null)
})

test('sensitive glob matching is case-insensitive on Windows', () => {
  if (process.platform !== 'win32') return
  assert.ok(matchSensitive(path.join(base, 'HOME', '.SSH', 'ID_RSA')))
})

test('classifyShell accepts prepared options', () => {
  const decision = classifyShell({
    command: 'Set-Content x.txt hi',
    cwd,
    shellMode: 'conservative',
  })
  assert.equal(decision.kind, 'shell-write')
})

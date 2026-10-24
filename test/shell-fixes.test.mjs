import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { classifyToolCall } from '../classify.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-shell-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })
const cwd = workspace

function call(command, config = {}) {
  return classifyToolCall({ name: 'pwsh', args: { command }, cwd, config })
}

test('a quoted literal before an expression is not a command', () => {
  assert.equal(call('"HEAD exists: " + (Test-Path \'.git\\config\')'), null)
})

test('reading a configuration file is not a configuration write', () => {
  assert.equal(call('Get-Content .git\\config'), null)
  assert.equal(call('Get-Content .bashrc'), null)
})

test('redirecting into a configuration file is still high risk', () => {
  const decision = call('echo x > .bashrc')
  assert.equal(decision.kind, 'config-write')
  assert.equal(decision.risk, 'high')
})

test('writing a configuration file with a write verb is still high risk', () => {
  const decision = call('Set-Content .git\\config -Value x')
  assert.equal(decision.kind, 'config-write')
})

test('git global options are not mistaken for a subcommand', () => {
  assert.equal(call('git -C .\\repo log --all'), null)
  assert.equal(call('git -C .\\repo status --short'), null)
  assert.equal(call('git --git-dir=.git log'), null)
  assert.equal(call('git -C .\\repo config --get user.name'), null)
})

test('mutating git subcommands are still gated', () => {
  const decision = call('git -C .\\repo push origin main')
  assert.equal(decision.kind, 'shell-write')
})

import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { classifyToolCall } from '../classify.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wag-noise-'))
const workspace = path.join(base, 'workspace')
fs.mkdirSync(workspace, { recursive: true })
const cwd = workspace

function call(command, config = {}) {
  return classifyToolCall({ name: 'pwsh', args: { command }, cwd, config })
}

test('a read-only foreach block is not a write', () => {
  assert.equal(call('foreach ($f in @("a.txt","b.txt")) { Get-Content $f }'), null)
})

test('a write inside a block is still caught', () => {
  const decision = call('foreach ($f in @("a.txt")) { Set-Content $f "x" }')
  assert.ok(decision)
  assert.equal(decision.kind, 'shell-write')
})

test('if blocks are judged by their body', () => {
  assert.equal(call('if (Test-Path a.txt) { Get-Content a.txt }'), null)
  assert.equal(call('if (Test-Path a.txt) { Set-Content a.txt x }').kind, 'shell-write')
})

test('ForEach-Object blocks are judged by their body', () => {
  assert.equal(call('Get-ChildItem . | ForEach-Object { $_.Name }'), null)
  assert.equal(call('Get-ChildItem . | ForEach-Object { "===== $($_.Name) =====" }'), null)
  assert.equal(call('Get-ChildItem . | ForEach-Object { Set-Content $_.Name x }').kind, 'shell-write')
})

test('bare strings and display-only cmdlets are not writes', () => {
  assert.equal(call('"=== done ==="'), null)
  assert.equal(call('"=== done ===" | Out-String'), null)
  assert.equal(call("'--- section ---'; Get-ChildItem ."), null)
})

test('a variable assignment is judged by its right-hand side', () => {
  assert.equal(call('$rows = @()'), null)
  assert.equal(call('$rows = Get-Content a.txt'), null)
  assert.equal(call('$map = @{ a = 1 }'), null)
  assert.equal(call('$x = Set-Content a.txt hi').kind, 'shell-write')
})

test('registry and property reads no longer look like writes', () => {
  assert.equal(call("Get-ItemProperty 'HKCU:\\Software\\Example' -ErrorAction SilentlyContinue"), null)
  assert.equal(call("Get-ItemProperty 'HKCU:\\Software\\Example' | ConvertFrom-Json"), null)
})

test('git remote only reads with -v / show', () => {
  assert.equal(call('git remote -v'), null)
  assert.equal(call('git remote show origin'), null)
  assert.equal(call('git remote add origin https://example.com/x.git').kind, 'shell-write')
})

test('the block splitter does not split on separators inside braces', () => {
  assert.equal(call('foreach ($f in @("a")) { $a = 1; $b = 2; Get-Content $f }'), null)
  assert.equal(call('foreach ($f in @("a")) { $a = 1; Set-Content $f x }').kind, 'shell-write')
})

test('a sub-expression executes its body', () => {
  assert.equal(call('$(Remove-Item a.txt)').kind, 'shell-write')
  assert.equal(call('$x = $(Set-Content a.txt hi)').kind, 'shell-write')
  assert.equal(call('$x = $(Get-Content a.txt)'), null)
  assert.equal(call('$(Get-Content a.txt).Length'), null)
})

test('brace-less control statements judge what follows the header', () => {
  assert.equal(call('if (Test-Path a.txt) Set-Content a.txt x').kind, 'shell-write')
  assert.equal(call("foreach ($f in @('a')) Set-Content $f x").kind, 'shell-write')
  assert.equal(call('if (Test-Path a.txt) Get-Content a.txt'), null)
})

test('an unbalanced command fails closed', () => {
  const decision = call('Get-ChildItem "a.txt')
  assert.ok(decision)
  assert.equal(decision.kind, 'shell-write')
})

test('Where-Object blocks are judged by their body', () => {
  assert.equal(call("Get-ChildItem . | Where-Object { $_.Name -like 'a*' }"), null)
  assert.equal(call('Get-ChildItem . | Where-Object { -not $_.Done }'), null)
  assert.equal(call('Get-ChildItem . | Where-Object { Remove-Item $_.FullName; $true }').kind, 'shell-write')
})

test('substitutions are judged even inside double-quoted strings', () => {
  assert.equal(call('"$(Remove-Item a.txt)"').kind, 'shell-write')
  assert.equal(call("'$(Remove-Item a.txt)'"), null)
  assert.equal(call('"$(Get-Content a.txt)"'), null)
})

test('a parenthesized expression with a property tail is a value', () => {
  assert.equal(call("($t -replace '\\s','').Length"), null)
  assert.equal(call('(Get-Content a.txt).Length'), null)
  assert.equal(call('(Get-ChildItem .).Count'), null)
  assert.equal(call('(Get-ChildItem .)[0]'), null)
})

test('a method call on a parenthesized expression stays a write', () => {
  assert.equal(call('(Get-Item a.txt).Delete()').kind, 'shell-write')
  assert.equal(call('(Get-Content a.txt).Clear()').kind, 'shell-write')
})

test('pure .NET static calls are values, IO and Environment are not', () => {
  assert.equal(call("([regex]::Matches($t, '[a-z]')).Count"), null)
  assert.equal(call('[math]::Round(1.5)'), null)
  assert.equal(call("[IO.File]::WriteAllText('a.txt','x')").kind, 'shell-write')
  assert.equal(call('[Environment]::Exit(0)').kind, 'shell-write')
})

test('the translation char-count command is read-only', () => {
  const command = "$t = Get-Content -Raw 'x.md'; $cjk = ([regex]::Matches($t, '[\\u4e00-\\u9fff]')).Count; $all = ($t -replace '\\s','').Length; \"CJK=$cjk ALLNOSPACE=$all\""
  assert.equal(call(command), null)
})

test('block aliases resolve to their cmdlets', () => {
  assert.equal(call('Get-ChildItem . | % { $_.Name }'), null)
  assert.equal(call('Get-ChildItem . | % { Set-Content $_.Name x }').kind, 'shell-write')
  assert.equal(call('Get-ChildItem . | ? { $_.Length -gt 0 }'), null)
})

test('here-strings: expandable bodies are scanned, literal bodies are not', () => {
  assert.equal(call('@"\n$(Remove-Item a.txt)\n"@').kind, 'shell-write')
  assert.equal(call("@'\n$(Remove-Item a.txt)\n'@"), null)
  assert.equal(call('@"\n$(Get-Content a.txt)\n"@'), null)
})

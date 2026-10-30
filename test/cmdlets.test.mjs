import assert from 'node:assert/strict'
import test from 'node:test'

import { classifyShell } from '../classify.js'

const cwd = process.cwd()
const isRead = command => classifyShell({ command, cwd }) === null
const isWrite = command => !isRead(command)

test('block cmdlets without a script block are reads', () => {
  assert.ok(isRead('Get-ChildItem | ForEach-Object Name'))
  assert.ok(isRead('Get-ChildItem | Where-Object PSIsContainer'))
  assert.ok(isRead('Get-ChildItem | % Name'))
  assert.ok(isRead('Get-ChildItem | ? PSIsContainer'))
})

test('a script block or an opaque variable still fails closed', () => {
  assert.ok(isWrite('Get-ChildItem | ForEach-Object { Remove-Item $_.FullName }'))
  assert.ok(isWrite('Get-ChildItem | Where-Object { $_.Length -gt 0 } | Out-File x.txt'))
  assert.ok(isWrite('Get-ChildItem | ForEach-Object $sb'))
  assert.ok(isWrite('Get-ChildItem | Where-Object -FilterScript $sb'))
})

test('node --check parses without running, everything else stays a write', () => {
  assert.ok(isRead('node --check index.js'))
  assert.ok(isRead('node -c index.js'))
  assert.ok(isWrite('node index.js'))
  assert.ok(isWrite('node --test test/'))
  assert.ok(isWrite('node -e "require(\'fs\').writeFileSync(\'x\',\'y\')"'))
})

test('read-only static methods are not writes', () => {
  assert.ok(isRead("[System.IO.File]::OpenRead('x')"))
  assert.ok(isRead("[System.IO.File]::ReadAllLines('x')"))
  assert.ok(isRead("[IO.Directory]::GetFiles('x')"))
  assert.ok(isRead("$_.Name.StartsWith('x',[StringComparison]::OrdinalIgnoreCase)"))
  assert.ok(isWrite("[System.IO.File]::WriteAllText('x','y')"))
  assert.ok(isWrite("[System.IO.File]::Delete('x')"))
})

test('discovery cmdlets and their aliases are reads', () => {
  for (const command of [
    'Get-Module',
    'gal',
    'Get-TimeZone',
    'gm',
    'gp',
    'gsv',
    "Read-Host 'x'",
    'cls',
    'Get-Uptime',
    'Get-NetTCPConnection',
    'Get-Content x | Select-Object -First 3 | Format-Table',
  ]) {
    assert.ok(isRead(command), command)
  }
})

test('write cmdlets stay gated', () => {
  for (const command of [
    'Set-Content a.txt 1',
    'Remove-Item a.txt',
    'New-Item -ItemType Directory x',
    'Out-File a.txt',
  ]) {
    assert.ok(isWrite(command), command)
  }
})

import assert from 'node:assert/strict'
import test from 'node:test'

import { classifyShell } from '../classify.js'

const cwd = process.cwd()
const judge = command => classifyShell({ command, cwd })

const highRisk = [
  'vssadmin delete shadows /all /quiet',
  'wbadmin delete catalog -quiet',
  'Disable-ComputerRestore -Drive C:\\',
  'New-LocalUser -Name test -Password $pw',
  'Add-LocalGroupMember -Group Administrators -Member test',
  'net localgroup administrators test /add',
  'Register-ScheduledTask -TaskName x -Action $a',
  'schtasks /change /tn x /tr y',
  'New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name x -Value y',
  'Remove-Service -Name x',
  'Set-MpPreference -DisableRealtimeMonitoring $true',
  'New-NetFirewallRule -DisplayName x -Direction Inbound -Action Allow',
  'manage-bde -off C:',
  'Enable-BitLocker -MountPoint C:',
  'Format-Volume -DriveLetter D',
]

test('no-path destructive commands are high risk', () => {
  for (const command of highRisk) {
    const decision = judge(command)
    assert.ok(decision !== null, command)
    assert.equal(decision.risk, 'high', command)
    assert.equal(decision.kind, 'destructive', command)
  }
})

test('the approval card explains what cannot be undone', () => {
  for (const command of highRisk) {
    const decision = judge(command)
    assert.match(decision.displayReason.zh, /^高危：命中「/, command)
    assert.match(decision.displayReason.zh, /风险：/, command)
    assert.ok(decision.displayReason.en.length > 40, command)
  }
})

test('reading the same subsystems is not high risk', () => {
  for (const command of [
    'vssadmin list shadows',
    'Get-LocalUser',
    'Get-ScheduledTask',
    'schtasks /query /tn x',
    'Get-MpPreference',
    'Get-NetFirewallRule',
    'manage-bde -status',
    'Get-BitLockerVolume',
  ]) {
    const decision = judge(command)
    assert.notEqual(decision?.risk, 'high', command)
  }
})

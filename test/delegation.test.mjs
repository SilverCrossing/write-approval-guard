import assert from 'node:assert/strict'
import test from 'node:test'

import { classifyToolCall } from '../classify.js'

const cwd = process.cwd()

function call(name, args, config = {}) {
  return classifyToolCall({ name, args, cwd, config })
}

test('starting a subagent needs approval', () => {
  const decision = call('subagent', { description: '改一行代码', prompt: '...' })
  assert.ok(decision)
  assert.equal(decision.kind, 'delegation')
  assert.match(decision.displayReason.zh, /委派子代理需要审批/)
  assert.match(decision.displayReason.zh, /改一行代码/)
})

test('workflow reports how many agent() calls the script makes', () => {
  const script = 'await agent("a"); await agent("b"); await agent("c")'
  const decision = call('workflow', { meta: { name: 'fan-out' }, script })
  assert.equal(decision.kind, 'delegation')
  assert.match(decision.reason, /3 agent\(\) call/)
  assert.match(decision.reason, /fan-out/)
})

test('a workflow without agent() calls says so', () => {
  const decision = call('workflow', { meta: { name: 'plain' }, script: 'return 1' })
  assert.match(decision.reason, /without agent\(\) calls/)
})

test('gateDelegation: false turns the gate off', () => {
  assert.equal(call('subagent', { prompt: 'x' }, { gateDelegation: false }), null)
})

test('non-delegation tools are unaffected', () => {
  assert.equal(call('list_agents', {}), null)
  assert.equal(call('send_message', { agent_id: 'x', message: 'y' }), null)
})

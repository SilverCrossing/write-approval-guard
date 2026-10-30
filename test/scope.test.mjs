import assert from 'node:assert/strict'
import test from 'node:test'

import { createSessionOverrides, matchWorkspace, normalizeWorkspaces, sessionKey } from '../scope.js'

const MODES = new Set(['all', 'workspace', 'risky'])
const win = process.platform === 'win32'
const root = win ? 'D:\\docs' : '/docs'
const nested = win ? 'D:\\docs\\sub' : '/docs/sub'
const sibling = win ? 'D:\\docs-archive' : '/docs-archive'

test('workspace roots match by whole path segment', () => {
  const entries = normalizeWorkspaces([{ root, mode: 'workspace' }], 'workspaces', MODES)
  assert.equal(entries.length, 1)
  assert.equal(matchWorkspace(nested, entries)?.mode, 'workspace')
  assert.equal(matchWorkspace(root, entries)?.root, root)
  assert.equal(matchWorkspace(sibling, entries), null)
})

test('the most specific binding wins', () => {
  const entries = normalizeWorkspaces([
    { root, mode: 'all' },
    { root: nested, mode: 'workspace' },
  ], 'workspaces', MODES)
  assert.equal(matchWorkspace(nested, entries)?.mode, 'workspace')
  assert.equal(matchWorkspace(root, entries)?.mode, 'all')
})

test('relative and malformed roots are refused with a warning', () => {
  const warnings = []
  const entries = normalizeWorkspaces([
    'not-an-object',
    { root: 'relative/dir', mode: 'workspace' },
    { root, mode: 'nonsense' },
    { root: '  ', mode: 'workspace' },
    { root, mode: 'workspace' },
  ], 'workspaces', MODES, message => warnings.push(message))
  assert.equal(entries.length, 1)
  assert.equal(warnings.length, 4)
})

test('case-insensitive matching follows the platform', () => {
  const entries = normalizeWorkspaces([{ root, mode: 'workspace' }], 'workspaces', MODES)
  if (!win) {
    assert.equal(matchWorkspace(root, entries)?.mode, 'workspace')
    return
  }
  assert.equal(matchWorkspace(root.toUpperCase(), entries)?.mode, 'workspace')
  assert.equal(matchWorkspace(sibling.toUpperCase(), entries), null)
})

test('missing or empty cwd never matches', () => {
  const entries = normalizeWorkspaces([{ root, mode: 'workspace' }], 'workspaces', MODES)
  assert.equal(matchWorkspace(undefined, entries), null)
  assert.equal(matchWorkspace('', entries), null)
  assert.equal(matchWorkspace(root, []), null)
})

test('session overrides merge and are bounded', () => {
  const overrides = createSessionOverrides(2)
  overrides.patch('a', { gateWrites: 'workspace' })
  overrides.patch('a', { mode: 'off' })
  assert.deepEqual(overrides.get('a'), { gateWrites: 'workspace', mode: 'off' })
  overrides.patch('b', { mode: 'enforce' })
  overrides.patch('c', { mode: 'enforce' })
  assert.equal(overrides.size, 2)
  assert.equal(overrides.get('a'), undefined)
})

test('deleting an override and patching an empty one both clear it', () => {
  const overrides = createSessionOverrides()
  overrides.patch('a', { mode: 'off' })
  overrides.delete('a')
  assert.equal(overrides.get('a'), undefined)
  overrides.patch('b', { mode: undefined })
  assert.equal(overrides.get('b'), undefined)
})

test('sessionKey prefers the session id and tolerates an agent-less call', () => {
  assert.equal(sessionKey({ id: 'a', session: { id: 's1' } }), 's1')
  assert.equal(sessionKey({ id: 'a' }), '')
  assert.equal(sessionKey(undefined), '')
})

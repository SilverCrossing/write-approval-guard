import assert from 'node:assert/strict'
import test from 'node:test'

import * as classify from '../classify.js'

test('the change-summary digest is not exported any more', () => {
  assert.equal(classify.summarizeChange, undefined)
})

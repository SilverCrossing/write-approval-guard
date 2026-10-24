import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { createLogger, localTimestamp } from '../log.js'

function tempDir(name) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `guard-log-${name}-`))
}

function dayFile(dir, date = new Date()) {
  const pad = value => String(value).padStart(2, '0')
  const day = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
  return path.join(dir, `${day}.log`)
}

test('writes one JSON line per event into the date file', () => {
  const dir = tempDir('write')
  const logger = createLogger('demo', { logDir: dir })
  logger.write({ event: 'ask', tool: 'write', target: 'D:\\x' })
  logger.write({ event: 'deny', tool: 'pwsh' })
  const lines = fs.readFileSync(dayFile(dir), 'utf8').trim().split('\n')
  assert.equal(lines.length, 2)
  const first = JSON.parse(lines[0])
  assert.equal(first.event, 'ask')
  assert.equal(first.tool, 'write')
  assert.match(first.ts, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$/)
})

test('keeps recent files and deletes files older than the retention window', () => {
  const dir = tempDir('retention')
  fs.mkdirSync(dir, { recursive: true })
  const old = path.join(dir, '2020-01-01.log')
  const keep = path.join(dir, '2020-01-02.log')
  fs.writeFileSync(old, '{}\n')
  fs.writeFileSync(keep, '{}\n')
  const ancient = new Date('2020-01-01T00:00:00Z')
  fs.utimesSync(old, ancient, ancient)
  fs.utimesSync(keep, new Date(), new Date())

  const logger = createLogger('demo', { logDir: dir, logRetentionDays: 7 })
  logger.write({ event: 'ask' })

  assert.equal(fs.existsSync(old), false)
  assert.equal(fs.existsSync(keep), true)
})

test('log: false writes nothing', () => {
  const dir = tempDir('off')
  const logger = createLogger('demo', { logDir: dir, log: false })
  logger.write({ event: 'ask' })
  assert.equal(fs.readdirSync(dir).length, 0)
})

test('a broken log directory never throws', () => {
  const root = tempDir('broken')
  const file = path.join(root, 'not-a-dir')
  fs.writeFileSync(file, 'x')
  const logger = createLogger('demo', { logDir: file })
  assert.doesNotThrow(() => logger.write({ event: 'ask' }))
})

test('localTimestamp carries an explicit offset', () => {
  assert.match(localTimestamp(new Date('2026-10-24T12:38:35.123Z')), /^2026-10-24T\d{2}:\d{2}:35\.123[+-]\d{2}:\d{2}$/)
})

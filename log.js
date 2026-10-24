/**
 * Append-only JSONL log for one guard plugin, split by local date.
 *
 * Each event is one line: `{ ts, event, ...fields }`. Files live under
 * `<DSH_HOME>/logs/<plugin>/YYYY-MM-DD.log` unless `logDir` overrides it.
 * Files older than `logRetentionDays` are deleted on the first write of the
 * process and then at most once every six hours.
 *
 * Logging must never break the guard: every failure is swallowed after a
 * console warning.
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export const DEFAULT_RETENTION_DAYS = 7
const CLEANUP_INTERVAL_MS = 6 * 60 * 60 * 1000

function defaultHome() {
  const configured = process.env.DSH_HOME
  return typeof configured === 'string' && configured.trim() !== ''
    ? configured
    : path.join(os.homedir(), '.dsh')
}

function pad(value, width = 2) {
  return String(value).padStart(width, '0')
}

/** Local ISO-8601 timestamp with an explicit offset (`2026-10-24T20:38:35.123+08:00`). */
export function localTimestamp(date) {
  const offsetMinutes = -date.getTimezoneOffset()
  const sign = offsetMinutes >= 0 ? '+' : '-'
  const hours = pad(Math.floor(Math.abs(offsetMinutes) / 60))
  const minutes = pad(Math.abs(offsetMinutes) % 60)
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}${sign}${hours}:${minutes}`
}

function dayKey(date) {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
}

/**
 * Create a logger bound to one plugin name and its normalized config.
 * @returns {{ write(event: object): void, directory: string }}
 */
export function createLogger(name, config = {}) {
  const enabled = config.log !== false
  const directory = typeof config.logDir === 'string' && config.logDir.trim() !== ''
    ? path.resolve(config.logDir)
    : path.join(defaultHome(), 'logs', name)
  const retentionDays = Number.isFinite(config.logRetentionDays)
    ? config.logRetentionDays
    : DEFAULT_RETENTION_DAYS

  let currentDay = ''
  let currentFile = ''
  let lastCleanup = 0

  function cleanup(now) {
    if (!(retentionDays > 0)) return
    if (now.getTime() - lastCleanup < CLEANUP_INTERVAL_MS) return
    lastCleanup = now.getTime()
    let entries
    try {
      entries = fs.readdirSync(directory)
    } catch {
      return
    }
    const cutoff = now.getTime() - retentionDays * 24 * 60 * 60 * 1000
    for (const entry of entries) {
      if (!/^\d{4}-\d{2}-\d{2}\.log$/.test(entry)) continue
      const file = path.join(directory, entry)
      try {
        if (fs.statSync(file).mtimeMs < cutoff) fs.unlinkSync(file)
      } catch {
        // A busy or already-removed file is not worth failing over.
      }
    }
  }

  function openFile(now) {
    const day = dayKey(now)
    if (day === currentDay && currentFile !== '') return
    fs.mkdirSync(directory, { recursive: true })
    currentDay = day
    currentFile = path.join(directory, `${day}.log`)
    cleanup(now)
  }

  return {
    directory,
    write(event) {
      if (!enabled) return
      const now = new Date()
      try {
        openFile(now)
        fs.appendFileSync(currentFile, `${JSON.stringify({ ts: localTimestamp(now), ...event })}\n`)
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        console.warn(`[${name}] cannot write log: ${message}`)
      }
    },
  }
}

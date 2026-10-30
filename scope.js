/**
 * Scope resolution shared by the guard plugins: which gate applies to one call.
 *
 * Two layers sit above the configured default:
 *
 *   - workspace bindings — `config.workspaces: [{ root, mode }]`, matched by the
 *     most specific absolute root that contains the session directory. They live
 *     in the profile patch, so they survive a restart.
 *   - session overrides — an in-memory `session.id -> { mode, gateWrites }` map
 *     written by the human-only slash command. It is deliberately lost on
 *     restart: a safety switch must fall back to the stricter configured value.
 *
 * Keys are `session.id` rather than `agent.id` because a session is what a human
 * addresses; a subagent runs in its own session, so an override cannot widen a
 * child by accident. A call without a session maps to the empty key, which keeps
 * headless callers (and the tests) on one process-wide bucket.
 */
import path from 'node:path'

/** Upper bound on remembered session overrides before the oldest is evicted. */
export const SESSION_OVERRIDE_CAP = 512

function platformKey(value) {
  return process.platform === 'win32' ? value.toLowerCase() : value
}

/**
 * Normalize `config.workspaces` into sorted `{ root, absolute, key, mode }`
 * entries. Relative roots are refused: they would resolve against the plugin
 * process directory rather than the session, silently widening the scope — the
 * same trap `sandboxPolicy.workspaceRoot` sets for a desktop profile.
 */
export function normalizeWorkspaces(value, configKey, modes, warn = () => {}) {
  if (value === undefined) return []
  if (!Array.isArray(value)) {
    warn(`config.${configKey} must be an array of { root, mode }; ignoring it`)
    return []
  }
  const entries = []
  for (const raw of value) {
    if (raw === null || typeof raw !== 'object') {
      warn(`config.${configKey} entry must be an object { root, mode }; skipped`)
      continue
    }
    const root = typeof raw.root === 'string' ? raw.root.trim() : ''
    const mode = raw.mode ?? raw.gateWrites
    if (root === '') {
      warn(`config.${configKey} entry without a root; skipped`)
      continue
    }
    if (typeof mode !== 'string' || !modes.has(mode)) {
      warn(`config.${configKey} entry "${root}" has an unknown mode; skipped`)
      continue
    }
    if (!path.isAbsolute(root)) {
      warn(`config.${configKey} entry "${root}" is not absolute; skipped (it would resolve against the plugin process, not the session)`)
      continue
    }
    const absolute = path.resolve(root)
    entries.push({ root, absolute, key: platformKey(absolute), mode })
  }
  // Longest root first, so the most specific binding wins.
  entries.sort((a, b) => b.key.length - a.key.length)
  return entries
}

/**
 * The binding whose root contains `cwd`, or null. Matching is on whole path
 * segments — `D:\docs` does not match `D:\docs-old` — and the comparison is
 * case-insensitive only where the platform is.
 */
export function matchWorkspace(cwd, entries) {
  if (typeof cwd !== 'string' || cwd.trim() === '' || entries.length === 0) return null
  const candidate = platformKey(path.resolve(cwd))
  for (const entry of entries) {
    if (candidate === entry.key) return entry
    const prefix = entry.key.endsWith(path.sep) ? entry.key : entry.key + path.sep
    if (candidate.startsWith(prefix)) return entry
  }
  return null
}

/** Bounded `session.id -> override` map used by the slash commands. */
export function createSessionOverrides(cap = SESSION_OVERRIDE_CAP) {
  const map = new Map()
  const limit = Number.isFinite(cap) && cap > 0 ? Math.floor(cap) : SESSION_OVERRIDE_CAP
  return {
    get(key) {
      return typeof key === 'string' ? map.get(key) : undefined
    },
    /** Merge one partial override; an entry that ends up empty is removed. */
    patch(key, partial) {
      if (typeof key !== 'string' || partial === null || typeof partial !== 'object') return
      const next = { ...(map.get(key) ?? {}), ...partial }
      for (const field of Object.keys(next)) {
        if (next[field] === undefined || next[field] === null) delete next[field]
      }
      map.delete(key)
      if (Object.keys(next).length === 0) return
      map.set(key, next)
      while (map.size > limit) {
        const oldest = map.keys().next().value
        if (oldest === undefined) return
        map.delete(oldest)
      }
    },
    delete(key) {
      if (typeof key === 'string') map.delete(key)
    },
    get size() {
      return map.size
    },
  }
}

/** The session key one call belongs to; '' when it has no session. */
export function sessionKey(agent) {
  const id = agent !== null && typeof agent === 'object' ? agent.session?.id : undefined
  return typeof id === 'string' ? id : ''
}

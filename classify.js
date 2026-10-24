/**
 * Pure classification for the write-approval guard.
 *
 * Every tool call answers three questions:
 *   1. does it modify the filesystem?       → one approval;
 *   2. is it destructive or system-level?   → a second, separate confirmation;
 *   3. does it read a secret-bearing file?  → one approval.
 *
 * Deliberately dependency-free (node:fs + node:path only) so the rules can be
 * unit tested outside the Harness process.
 */
import fs from 'node:fs'
import path from 'node:path'

const WINDOWS = process.platform === 'win32'

/**
 * Tools that write files, and how to read their target paths from the call.
 *
 * `dsh-safety-toolkit` replaces the native tools with `safe_*` names
 * (`safe_write` / `safe_edit` / `multi_edit` / `safe_rollback`), and its
 * governance row hides `write`/`edit` from the model entirely, so both
 * spellings must be covered or the guard is bypassed by the replacement.
 */
const WRITE_TOOL_PATHS = Object.freeze({
  write: args => [args.file_path],
  edit: args => [args.file_path],
  safe_write: args => [args.filepath],
  safe_edit: args => [args.filepath],
  safe_rollback: args => [args.filepath],
  multi_edit: args => (Array.isArray(args.edits)
    ? args.edits.map(entry => (entry !== null && typeof entry === 'object' ? entry.file : undefined))
    : []),
})

/** Tools that run project code but declare no file path. */
const EXECUTION_WRITE_TOOLS = new Set(['test_runner'])

/** Tools whose path argument is read. */
const READ_TOOLS = Object.freeze({ read: 'file_path', read_image: 'file_path' })

/** Tools with no write or sensitive-read meaning; never gated. */
const READ_ONLY_TOOLS = new Set(['syntax_check', 'safe_backups'])

/** Every tool name this plugin understands; anything else is "unknown". */
const KNOWN_TOOLS = new Set([
  ...Object.keys(WRITE_TOOL_PATHS),
  ...Object.keys(READ_TOOLS),
  'pwsh',
  'bash',
  'shell',
  ...EXECUTION_WRITE_TOOLS,
  ...READ_ONLY_TOOLS,
  'grep',
  'glob',
])

const SHELL_TOOLS = new Set(['pwsh', 'bash', 'shell'])

/**
 * Locations that normally hold credentials, private keys, or browser session
 * data. Matched against the lexical path and its real path.
 */
export const DEFAULT_SENSITIVE_PATTERNS = Object.freeze([
  '**/.env',
  '**/.env.*',
  '**/*.env',
  '**/.envrc',
  '**/.npmrc',
  '**/.pypirc',
  '**/.netrc',
  '**/.git-credentials',
  '**/*.pem',
  '**/*.key',
  '**/*.pfx',
  '**/*.p12',
  '**/*.keystore',
  '**/*.jks',
  '**/*.ppk',
  '**/id_rsa',
  '**/id_rsa.*',
  '**/id_ed25519',
  '**/id_ed25519.*',
  '**/id_ecdsa',
  '**/id_ecdsa.*',
  '**/.config',
  '**/.config/**',
  '**/.ssh',
  '**/.ssh/**',
  '**/.aws',
  '**/.aws/**',
  '**/.azure',
  '**/.azure/**',
  '**/.gnupg',
  '**/.gnupg/**',
  '**/.kube',
  '**/.kube/**',
  '**/.docker/config.json',
  '**/.dsh/.credentials.yaml',
  '**/.dsh/.credentials.*',
  '**/credentials',
  '**/credentials.*',
  '**/secrets.*',
  '**/*.secret',
  '**/*.password',
  '**/passwords.*',
  '**/Login Data',
  '**/Cookies',
  '**/Local State',
  '**/logins.json',
  '**/key4.db',
])

/** System locations: writing here is high risk on every platform. */
export function defaultSystemRoots() {
  if (!WINDOWS) {
    return [
      '/etc',
      '/usr',
      '/bin',
      '/sbin',
      '/boot',
      '/System',
      '/Library',
      '/private/etc',
      '/var/lib',
      '/var/db',
      '/dev',
      '/proc',
      '/sys',
    ]
  }
  const roots = new Set([
    'C:\\Windows',
    'C:\\Program Files',
    'C:\\Program Files (x86)',
    'C:\\ProgramData',
    'C:\\Boot',
    'C:\\Recovery',
    'C:\\System Volume Information',
  ])
  const fromEnvironment = [
    process.env.SystemRoot,
    process.env.windir,
    process.env.ProgramFiles,
    process.env['ProgramFiles(x86)'],
    process.env.ProgramW6432,
  ]
  for (const value of fromEnvironment) {
    if (typeof value === 'string' && value.trim() !== '') roots.add(path.resolve(value))
  }
  return [...roots]
}

/** Labels used in the approval text so the user knows what triggered it. */
const HIGH_RISK_LABELS = Object.freeze({
  disk: '磁盘/格式化操作 (disk or format)',
  delete: '递归或通配删除 (recursive or wildcard delete)',
  system: '系统配置修改 (system configuration)',
  perm: '权限/所有权修改 (permissions or ownership)',
})

/**
 * Shell patterns that deserve the second confirmation. Ordered so the most
 * specific reason wins; the first match is reported to the user.
 */
const HIGH_RISK_PATTERNS = Object.freeze([
  ['disk', /\bformat(?:\.com)?\s+[a-z]:/i],
  ['disk', /\bdiskpart(?:\.exe)?\b/i],
  ['disk', /\b(?:clear|initialize|format|set|remove|resize|new)-disk\b/i],
  ['disk', /\b(?:clear|initialize|format|set|remove|resize|new)-partition\b/i],
  ['disk', /\bmkfs(?:\.[a-z0-9]+)?\b/i],
  ['disk', /\bdd\s+if=/i],
  ['disk', /\bcipher(?:\.exe)?\b[^\n]*\/w\b/i],
  ['delete', /\b(?:remove-item|ri)\b[^\n]*\s-(?:recurse|r)\b/i],
  ['delete', /\b(?:remove-item|ri)\b[^\n]*\s\*(?:\s|$)/i],
  ['delete', /\brm\b[^\n]*\s-[a-z]*r[a-z]*\b/i],
  ['delete', /\b(?:rd|rmdir)\b[^\n]*\/s\b/i],
  ['delete', /\b(?:del|erase)\b[^\n]*\/(?:[a-z]*[fs])/i],
  ['delete', /\b(?:del|erase)\b[^\n]*\*\.\*/i],
  ['system', /\b(?:reg|regedit)(?:\.exe)?\s+(?:add|delete|import|copy|restore)\b/i],
  ['system', /\b(?:set|new)-itemproperty\b[^\n]*\b(?:hklm|hkey_local_machine|hku|hkey_users)\b/i],
  ['system', /\b(?:sc|sc\.exe)\s+(?:delete|config|create|failure|sdset|start|stop)\b/i],
  ['system', /\b(?:set|new|stop|start|restart|disable|enable|suspend|resume)-service\b/i],
  ['system', /\bbcdedit\b|\bbootrec\b|\bfixmbr\b|\bfixboot\b/i],
  ['system', /\bnetsh\b/i],
  ['system', /\bshutdown\b|\brestart-computer\b|\bstop-computer\b/i],
  ['system', /\bschtasks\b[^\n]*\/create\b/i],
  ['system', /\b(?:setx|set-executionpolicy)\b/i],
  ['system', /\b(?:enable|disable)-windowsoptionalfeature\b|\b(?:add|remove)-windowscapability\b/i],
  ['system', /\bhosts\b[^\n]*(?:set-content|add-content|out-file|>)/i],
  ['system', /\bwmic\b[^\n]*\b(?:delete|call\s+create)\b/i],
  ['perm', /\bicacls(?:\.exe)?\b[^\n]*\/(?:reset|grant|deny|setowner|remove)\b/i],
  ['perm', /\bcacls(?:\.exe)?\b[^\n]*\/(?:g|r|p|d)\b/i],
  ['perm', /\btakeown(?:\.exe)?\b[^\n]*\/f\b/i],
  ['perm', /\b(?:chmod|chown|chgrp)\b[^\n]*\s-R\b/i],
  ['perm', /\b(?:chmod|chown)\b[^\n]*\b(?:777|000|4755)\b/i],
])

/** Commands that only read, so a plain invocation needs no approval. */
const READ_ONLY_COMMANDS = new Set([
  'ls', 'dir', 'get-childitem', 'gci', 'pwd', 'get-location', 'gl', 'cd', 'set-location',
  'push-location', 'pop-location', 'cat', 'type', 'get-content', 'gc', 'more', 'less',
  'head', 'tail', 'grep', 'rg', 'findstr', 'select-string', 'sls', 'get-item', 'gi',
  'test-path', 'resolve-path', 'split-path', 'join-path', 'measure', 'measure-object',
  'select-object', 'select', 'where-object', 'sort', 'sort-object', 'group-object',
  'format-table', 'ft', 'format-list', 'fl', 'convertto-json', 'convertto-csv',
  'get-command', 'gcm', 'get-help', 'help', 'man', 'get-process', 'ps', 'tasklist',
  'get-service', 'whoami', 'hostname', 'id', 'uname', 'ipconfig', 'netstat',
  'systeminfo', 'ver', 'where', 'which', 'echo', 'write-output', 'write-host',
  'out-null', 'get-date', 'date', 'printenv', 'env', 'tree', 'wc', 'du', 'df',
  'stat', 'file', 'cmp', 'diff', 'comm', 'basename', 'dirname', 'realpath',
])

/** Commands that write, so a plain invocation needs one approval. */
const WRITE_COMMANDS = new Set([
  'set-content', 'add-content', 'clear-content', 'out-file', 'new-item', 'copy-item',
  'move-item', 'rename-item', 'remove-item', 'ri', 'set-item', 'new-itemproperty',
  'set-itemproperty', 'export-csv', 'export-clixml', 'tee-object', 'tee', 'copy',
  'xcopy', 'robocopy', 'move', 'ren', 'rename', 'del', 'erase', 'rd', 'rmdir', 'md',
  'mkdir', 'mklink', 'attrib', 'cacls', 'icacls', 'takeown', 'rm', 'mv', 'cp', 'ln',
  'truncate', 'touch', 'chmod', 'chown', 'chgrp', 'patch', 'dd', 'install', 'uninstall',
  'npm', 'pnpm', 'yarn', 'bun', 'pip', 'pip3', 'cargo', 'go', 'gem', 'composer',
  'dotnet', 'make', 'cmake', 'docker', 'kubectl', 'helm', 'terraform', 'ansible',
  'vagrant', 'systemctl', 'pacman', 'apt', 'apt-get', 'dnf', 'yum', 'brew', 'choco',
  'scoop', 'winget',
])

/** Git subcommands that only read. Everything else is treated as a write. */
const GIT_READ_SUBCOMMANDS = new Set([
  'status', 'log', 'diff', 'show', 'rev-parse', 'describe', 'blame', 'ls-files',
  'ls-tree', 'cat-file', 'shortlog', 'grep', 'version', 'help',
])

const DRIVE_TOKEN = /(?:^|[\s"'`(=[,;|&<>])([A-Za-z]:[\\/][^\s"'`;|&<>)]*)/g
const UNC_TOKEN = /(?:^|[\s"'`(=[,;|&<>])(\\\\[^\s"'`;|&<>)]+)/g
const POSIX_TOKEN = /(?:^|[\s"'`(=[,;|&<>])(\/{1,2}[^\s"'`;|&<>)]*)/g

/** A shell redirection that writes a file; `2>&1` and `=>` are excluded. */
const REDIRECT = /(?:^|[^0-9=<])>{1,2}(?!&)\s*[^\s|&;)]/

/** A sensitive file mentioned anywhere in a command line. */
const SENSITIVE_TEXT = /(?:^|[\s"'`(=:,\\/])(?:\.env(?:\.[\w.-]+)?|\.envrc|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.config|id_rsa(?:\.[\w.-]+)?|id_ed25519(?:\.[\w.-]+)?|id_ecdsa(?:\.[\w.-]+)?|credentials(?:\.[\w.-]+)?|secrets?(?:\.[\w.-]+)?|[^\s"'`;|&<>\/\\]+\.(?:pem|key|pfx|p12|keystore|jks|ppk|password|config|env))(?=$|[\s"'`;|&<>),])/i

/** A bare file name (or `grep` include glob) that names a sensitive file. */
const SENSITIVE_NAME = /^(?:\.env(?:\.[\w.-]+)?|\.envrc|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.config|id_(?:rsa|ed25519|ecdsa)(?:\.[\w.-]+)?|credentials(?:\.[\w.-]+)?|secrets?(?:\.[\w.-]+)?|.*\.(?:pem|key|pfx|p12|keystore|jks|ppk|password|config|env))$/i

function stripTrailingSeparator(value) {
  if (value.length <= 1) return value
  // Keep `C:\` intact: dropping its separator turns it into a drive-relative path.
  if (/^[A-Za-z]:[\\/]$/.test(value)) return value
  return value.replace(/[\\/]+$/, '')
}

/** Comparison key: Windows paths are case-insensitive. */
function key(value) {
  const stripped = stripTrailingSeparator(value)
  return WINDOWS ? stripped.toLowerCase() : stripped
}

export function isInside(root, target) {
  const r = key(root)
  const t = key(target)
  if (r === t) return true
  const relative = path.relative(r, t)
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative)
}

/**
 * Resolve the real path, resolving the deepest existing ancestor when the
 * target itself does not exist yet. Defeats symlinks that point elsewhere.
 */
export function realpathDeep(target) {
  let current = path.resolve(target)
  const missing = []
  for (let depth = 0; depth < 64; depth += 1) {
    try {
      const real = fs.realpathSync.native
        ? fs.realpathSync.native(current)
        : fs.realpathSync(current)
      return path.resolve(real, ...missing)
    } catch {
      const parent = path.dirname(current)
      if (parent === current) return path.resolve(target)
      missing.unshift(path.basename(current))
      current = parent
    }
  }
  return path.resolve(target)
}

const regexCache = new Map()

function globToRegExp(glob) {
  const cached = regexCache.get(glob)
  if (cached !== undefined) return cached
  let out = '^'
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index]
    if (char === '*') {
      if (glob[index + 1] === '*') {
        out += '.*'
        index += 1
      } else {
        out += '[^/]*'
      }
    } else if (char === '?') {
      out += '[^/]'
    } else if ('\\^$.|+()[]{}'.includes(char)) {
      out += `\\${char}`
    } else {
      out += char
    }
  }
  const regex = new RegExp(`${out}$`, WINDOWS ? 'i' : '')
  regexCache.set(glob, regex)
  return regex
}

function normalizeForGlob(value) {
  return value.replace(/\\/g, '/').replace(/\/{2,}/g, '/')
}

/** Absolute path for a tool argument, or null when no base directory is known. */
function absoluteOf(value, cwd) {
  if (path.isAbsolute(value)) return path.normalize(value)
  if (typeof cwd === 'string' && path.isAbsolute(cwd)) return path.resolve(cwd, value)
  return null
}

/** Return the first sensitive pattern matching `target`, or null. */
export function matchSensitive(target, patterns = DEFAULT_SENSITIVE_PATTERNS) {
  if (typeof target !== 'string' || target.trim() === '') return null
  const value = target.trim()
  const candidate = path.isAbsolute(value)
    ? normalizeForGlob(path.normalize(value))
    : `./${normalizeForGlob(value)}`
  for (const pattern of patterns) {
    if (typeof pattern !== 'string' || pattern.trim() === '') continue
    if (globToRegExp(pattern.trim()).test(candidate)) return pattern
  }
  return null
}

function matchSensitiveAny(candidates, patterns) {
  for (const candidate of candidates) {
    if (typeof candidate !== 'string' || candidate === '') continue
    const hit = matchSensitive(candidate, patterns)
    if (hit !== null) return hit
  }
  return null
}

function looksSensitiveName(value) {
  const base = path.basename(value.replace(/[\\/]+$/, ''))
  return SENSITIVE_NAME.test(base)
}

function isSystemPath(target, roots) {
  for (const root of roots) {
    if (typeof root === 'string' && isInside(root, target)) return true
  }
  return false
}

function short(value, max = 280) {
  const text = String(value)
  return text.length > max ? `${text.slice(0, max)}…` : text
}

function decision(kind, risk, en, zh) {
  return { kind, risk, reason: en, displayReason: { en, zh } }
}

/** Absolute-path tokens mentioned in a command line. */
function collectAbsoluteTokens(command) {
  const tokens = new Set()
  for (const regex of [DRIVE_TOKEN, UNC_TOKEN, POSIX_TOKEN]) {
    regex.lastIndex = 0
    let match
    while ((match = regex.exec(command)) !== null) tokens.add(match[1])
    regex.lastIndex = 0
  }
  return [...tokens]
}

/** The command word at the start of one pipeline segment. */
function firstToken(segment) {
  let text = segment.trim()
  if (text === '') return ''
  text = text.replace(/^[&(]\s*/, '')
  const assignment = /^[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+/.exec(text)
  if (assignment !== null) text = text.slice(assignment[0].length)
  const quoted = /^["']([^"']+)["']/.exec(text)
  if (quoted !== null) return quoted[1].toLowerCase()
  const match = /^(\S+)/.exec(text)
  return match === null ? '' : match[1].replace(/^["']|["']$/g, '').toLowerCase()
}

function commandName(token) {
  const trimmed = token.replace(/[\\/]+$/, '')
  return path.basename(trimmed).replace(/\.(?:exe|cmd|bat|com|ps1|sh)$/i, '').toLowerCase()
}

function gitVerdict(segment) {
  const words = segment.trim().split(/\s+/).slice(1).filter(word => !word.startsWith('-'))
  const subcommand = (words[0] ?? '').toLowerCase()
  if (subcommand === '') return 'read'
  if (GIT_READ_SUBCOMMANDS.has(subcommand)) return 'read'
  if (subcommand !== 'config') return 'write'
  return segment.includes('--get') ? 'read' : 'write'
}

/**
 * `read` when the segment certainly only reads, otherwise `write`.
 * Unknown commands count as writes unless the shell mode is `lenient`.
 */
function segmentVerdict(segment, shellMode) {
  const token = firstToken(segment)
  if (token === '') return 'read'
  const name = commandName(token)
  if (READ_ONLY_COMMANDS.has(name)) return 'read'
  if (name === 'git') return gitVerdict(segment)
  if (name === 'sed' || name === 'perl') return /(?:^|\s)-\w*i/.test(segment) ? 'write' : 'read'
  if (WRITE_COMMANDS.has(name)) return 'write'
  return shellMode === 'lenient' ? 'read' : 'write'
}

function commandSegments(command) {
  return command
    .split(/\r?\n|;|&&|\|\||\|/)
    .map(segment => segment.trim())
    .filter(segment => segment !== '')
}

function matchHighRisk(command) {
  for (const [id, regex] of HIGH_RISK_PATTERNS) {
    const match = regex.exec(command)
    if (match !== null) return { id, match: match[0] }
  }
  return null
}

/** Classify one shell invocation. */
export function classifyShell({ command, workdir, cwd, systemRoots = defaultSystemRoots(), sensitivePatterns = DEFAULT_SENSITIVE_PATTERNS, shellMode = 'conservative' }) {
  if (typeof command !== 'string' || command.trim() === '') return null
  const text = command.trim()

  const highRisk = matchHighRisk(text)
  if (highRisk !== null) {
    const label = HIGH_RISK_LABELS[highRisk.id] ?? highRisk.id
    return decision(
      'destructive',
      'high',
      `High-risk command (${label}): ${short(text)}`,
      `高危：命中「${label}」，将执行：${short(text)}`,
    )
  }

  const tokens = collectAbsoluteTokens(text)
  const systemToken = tokens.find(token => isSystemPath(token, systemRoots)) ?? null
  const writes = REDIRECT.test(text) || commandSegments(text).some(segment => segmentVerdict(segment, shellMode) === 'write')

  if (writes) {
    let systemTarget = systemToken
    if (systemTarget === null && typeof workdir === 'string' && workdir.trim() !== '') {
      const absoluteWorkdir = absoluteOf(workdir.trim(), cwd)
      if (absoluteWorkdir !== null && isSystemPath(absoluteWorkdir, systemRoots)) systemTarget = absoluteWorkdir
    }
    if (systemTarget !== null) {
      return decision(
        'system-write',
        'high',
        `High-risk command touching a system location (${systemTarget}): ${short(text)}`,
        `高危：命令将修改系统位置（${systemTarget}），将执行：${short(text)}`,
      )
    }
    const sensitive = SENSITIVE_TEXT.test(text) || tokens.some(token => matchSensitive(token, sensitivePatterns) !== null)
    if (sensitive) {
      return decision(
        'sensitive-write',
        'normal',
        `Approval required before a command that writes a sensitive file: ${short(text)}`,
        `命令将写入敏感文件，需要审批：${short(text)}`,
      )
    }
    return decision(
      'shell-write',
      'normal',
      `Approval required before a command that may write files: ${short(text)}`,
      `命令可能写入文件，需要审批：${short(text)}`,
    )
  }

  const sensitive = SENSITIVE_TEXT.test(text) || tokens.some(token => matchSensitive(token, sensitivePatterns) !== null)
  if (sensitive) {
    return decision(
      'sensitive-read',
      'normal',
      `Approval required before a command that reads a sensitive file: ${short(text)}`,
      `命令将读取敏感文件，需要审批：${short(text)}`,
    )
  }
  return null
}

function classifyWrite(tool, value, cwd, { systemRoots, sensitivePatterns, exemptPaths }) {
  const target = value.trim()
  const absolute = absoluteOf(target, cwd)
  const real = absolute === null ? null : realpathDeep(absolute)

  for (const candidate of [absolute, real]) {
    if (candidate !== null && isSystemPath(candidate, systemRoots)) {
      return decision(
        'system-write',
        'high',
        `High-risk write to a system location: ${short(candidate)}`,
        `高危：将写入系统位置：${short(candidate)}`,
      )
    }
  }

  if (absolute !== null && exemptPaths.some(root => isInside(root, absolute))) return null

  const sensitive = matchSensitiveAny([absolute, real, target], sensitivePatterns) !== null || looksSensitiveName(target)
  if (sensitive) {
    return decision(
      'sensitive-write',
      'normal',
      `Approval required before writing a sensitive file: ${short(absolute ?? target)}`,
      `写入敏感文件需要审批：${short(absolute ?? target)}`,
    )
  }
  return decision(
    'write',
    'normal',
    `Approval required before writing: ${short(absolute ?? target)}`,
    `写操作需要审批：${short(absolute ?? target)}`,
  )
}

/** Classify every target of one call; the highest risk wins. */
function classifyWriteMany(tool, values, cwd, options) {
  let worst = null
  for (const value of values) {
    const candidate = classifyWrite(tool, value, cwd, options)
    if (candidate === null) continue
    if (worst === null || (worst.risk !== 'high' && candidate.risk === 'high')) worst = candidate
  }
  if (worst === null || values.length < 2) return worst
  return {
    ...worst,
    displayReason: {
      en: `${worst.displayReason.en} (${values.length} files in this call)`,
      zh: `${worst.displayReason.zh}（本次共 ${values.length} 个文件）`,
    },
  }
}

/**
 * `safe_rollback` writes an old snapshot over the current file. Say that
 * explicitly and name the snapshot, because it can silently replace edits made
 * after the snapshot was taken.
 */
function withRollbackNote(decision, args, value, cwd) {
  const absolute = absoluteOf(value.trim(), cwd) ?? value.trim()
  const named = typeof args.backup_name === 'string' && args.backup_name.trim() !== ''
  const snapshot = named ? args.backup_name.trim().slice(0, 60) : null
  const snapshotZh = snapshot ?? '最近一次改动前快照'
  const snapshotEn = snapshot ?? 'the most recent pre-change snapshot'
  const prefixZh = decision.risk === 'high' ? '高危：' : ''
  const prefixEn = decision.risk === 'high' ? 'High risk: ' : ''
  const sensitiveZh = decision.kind === 'sensitive-write' ? '（敏感文件）' : ''
  const sensitiveEn = decision.kind === 'sensitive-write' ? ' (sensitive file)' : ''
  return {
    ...decision,
    reason: `${prefixEn}Rollback will overwrite the current content: ${absolute} (snapshot: ${snapshotEn})${sensitiveEn}`,
    displayReason: {
      en: `${prefixEn}Rollback will overwrite the current content: ${absolute} (snapshot: ${snapshotEn})${sensitiveEn}`,
      zh: `${prefixZh}回滚会覆盖当前内容：${absolute}（快照：${snapshotZh}）${sensitiveZh}`,
    },
  }
}

function classifyRead(tool, value, cwd, { sensitivePatterns }) {
  const target = value.trim()
  const absolute = absoluteOf(target, cwd)
  const real = absolute === null ? null : realpathDeep(absolute)
  const sensitive = matchSensitiveAny([absolute, real, target], sensitivePatterns) !== null || looksSensitiveName(target)
  if (!sensitive) return null
  return decision(
    'sensitive-read',
    'normal',
    `Approval required before reading a sensitive file: ${short(absolute ?? target)}`,
    `读取敏感文件需要审批：${short(absolute ?? target)}`,
  )
}

function classifySearch(tool, args, cwd, { sensitivePatterns }) {
  const sensitivePath = typeof args.path === 'string' && args.path.trim() !== ''
    ? classifyRead(tool, args.path, cwd, { sensitivePatterns })
    : null
  if (sensitivePath !== null) return sensitivePath
  if (tool === 'grep' && typeof args.include === 'string' && looksSensitiveName(args.include)) {
    return decision(
      'sensitive-read',
      'normal',
      `Approval required before searching a sensitive file pattern: ${short(args.include)}`,
      `按敏感文件模式搜索需要审批：${short(args.include)}`,
    )
  }
  return null
}

/**
 * Classify one tool call.
 *
 * @param {object} input
 * @param {string} input.name tool name
 * @param {unknown} input.args parsed arguments
 * @param {string | null | undefined} input.cwd current session directory
 * @param {object} [input.config] normalized configuration
 * @returns {null | { kind: string, risk: 'normal' | 'high', reason: string, displayReason: { en: string, zh: string } }}
 */
export function classifyToolCall({ name, args, cwd, config = {} }) {
  if (typeof name !== 'string') return null
  const sensitivePatterns = Array.isArray(config.sensitivePaths) && config.sensitivePaths !== undefined
    ? config.sensitivePaths
    : DEFAULT_SENSITIVE_PATTERNS
  const systemRoots = [
    ...defaultSystemRoots(),
    ...(Array.isArray(config.extraSystemRoots) ? config.extraSystemRoots : []),
  ]
  const exemptPaths = Array.isArray(config.exemptPaths) ? config.exemptPaths : []
  const gateShell = config.gateShell !== false
  const shellMode = config.shellMode === 'lenient' || config.shellMode === 'off' ? config.shellMode : 'conservative'
  const sensitiveRisk = config.sensitiveReadConfirmations === 'double' ? 'high' : 'normal'
  const ignoreTools = Array.isArray(config.ignoreTools) ? config.ignoreTools : []
  if (ignoreTools.includes(name)) return null

  if (SHELL_TOOLS.has(name)) {
    if (!gateShell || shellMode === 'off') return null
    if (args === null || typeof args !== 'object') return null
    const result = classifyShell({
      command: args.command,
      workdir: args.workdir,
      cwd,
      systemRoots,
      sensitivePatterns,
      shellMode,
    })
    return escalate(result, sensitiveRisk)
  }

  const pathReader = WRITE_TOOL_PATHS[name]
  if (pathReader !== undefined) {
    if (args === null || typeof args !== 'object') return null
    const values = pathReader(args).filter(value => typeof value === 'string' && value.trim() !== '')
    if (values.length === 0) return null
    const decision = classifyWriteMany(name, values, cwd, { systemRoots, sensitivePatterns, exemptPaths })
    if (decision !== null && name === 'safe_rollback') {
      return withRollbackNote(decision, args, values[0], cwd)
    }
    return decision
  }

  if (EXECUTION_WRITE_TOOLS.has(name)) {
    if (!gateShell || shellMode === 'off') return null
    return decision(
      'shell-write',
      'normal',
      `Approval required before running project code: ${name}`,
      `运行项目代码需要审批：${name}`,
    )
  }

  const readField = READ_TOOLS[name]
  if (readField !== undefined) {
    if (args === null || typeof args !== 'object') return null
    const value = args[readField]
    if (typeof value !== 'string' || value.trim() === '') return null
    return escalate(classifyRead(name, value, cwd, { sensitivePatterns }), sensitiveRisk)
  }

  if (name === 'grep' || name === 'glob') {
    if (args === null || typeof args !== 'object') return null
    return escalate(classifySearch(name, args, cwd, { sensitivePatterns }), sensitiveRisk)
  }

  if (config.unknownTools === 'ask' && !KNOWN_TOOLS.has(name)) {
    return decision(
      'unknown-tool',
      'normal',
      `Approval required before calling an unrecognized tool: ${name}`,
      `未登记的工具需要审批：${name}`,
    )
  }

  return null
}

function escalate(result, sensitiveRisk) {
  if (result !== null && result.kind === 'sensitive-read' && sensitiveRisk === 'high') {
    return { ...result, risk: 'high' }
  }
  return result
}

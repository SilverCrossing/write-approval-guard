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
 *
 * Layout, top to bottom:
 *   1. tool tables       — which tool writes or reads which argument
 *   2. sensitive tables  — credential locations and file names
 *   3. config tables     — configuration and behavior files
 *   4. high-risk tables  — destructive shell patterns and their labels
 *   5. path helpers      — containment, realpath, glob matching
 *   6. decision shape    — the { kind, risk, reason, displayReason } contract
 *   7. command parsing   — tokenisation, git/sed special cases, shell verdicts
 *   8. classifiers       — classifyShell / classifyToolCall, the entry points
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

/**
 * .NET static types that only compute values. Every other `[Type]::` call is
 * judged as a write: `[IO.File]::WriteAllText` and `[Environment]::Exit` are why
 * this is an allowlist instead of a denylist.
 */
const READ_ONLY_STATICS = new Set([
  'regex', 'math', 'string', 'char', 'convert', 'datetime', 'timespan',
  'guid', 'uri', 'version', 'cultureinfo', 'encoding', 'bitconverter',
  // Pure-value enums: `[StringComparison]::OrdinalIgnoreCase` is an argument,
  // not an action, and it appeared inside otherwise read-only pipelines.
  'stringcomparison', 'stringsplitoptions', 'regexoptions',
])

/**
 * Read-only methods on types that also have write methods. `[IO.File]` cannot
 * join READ_ONLY_STATICS wholesale: that would whitelist `WriteAllText` too.
 */
const READ_ONLY_STATICS_METHODS = new Set([
  'file.openread', 'file.opentext', 'file.exists', 'file.getattributes',
  'file.readalltext', 'file.readalllines', 'file.readallbytes',
  'file.getlastwritetime', 'file.getcreationtime', 'file.getlastaccesstime',
  'directory.getfiles', 'directory.getdirectories', 'directory.exists',
  'path.combine', 'path.getfullpath', 'path.getfilename',
])

/** Tools that run project code but declare no file path. */
const EXECUTION_WRITE_TOOLS = new Set(['test_runner'])

/**
 * Tools that hand the agent autonomy instead of performing one action: they
 * schedule work for later or open automatic continuation rounds, so they keep
 * working while the user is away. Autonomy is the most destructive capability
 * in the set, so these take the second confirmation.
 *
 * 中文：这些不是“一次操作”，而是“把控制权交出去”——定时任务会在你离开后
 * 触发，目标会开启自动续轮。它们比单条命令破坏性更强，所以归为高危。
 */
const AUTONOMY_TOOLS = new Set(['schedule_create', 'schedule_update', 'create_goal'])

/**
 * `update_goal` only grants autonomy through `edit` (new objective or a higher
 * round cap) and `resume` (re-arm a paused goal). Completing, pausing or
 * blocking a goal reduces autonomy and stays ungated.
 */
const AUTONOMY_GOAL_ACTIONS = new Set(['edit', 'resume'])

/** One-line summary of what an autonomy tool will start or schedule. */
function autonomySummary(name, args) {
  const text = key => args !== null && typeof args === 'object' && typeof args[key] === 'string' ? args[key] : ''
  if (name === 'create_goal' || name === 'update_goal') return short(text('objective'))
  const at = args !== null && typeof args === 'object' ? args.at : undefined
  const timing = typeof at === 'string'
    ? at
    : at !== null && typeof at === 'object'
      ? [at.date, at.time, at.time_zone].filter(part => typeof part === 'string' && part !== '').join(' ')
      : ''
  return timing === '' ? short(text('prompt')) : `${short(text('prompt'))} @ ${short(timing, 60)}`
}

/** Tools whose path argument is read. */
const READ_TOOLS = Object.freeze({ read: 'file_path', read_image: 'file_path' })

/** Tools with no write or sensitive-read meaning; never gated. */
const READ_ONLY_TOOLS = new Set(['syntax_check', 'safe_backups'])

/**
 * Tools that create more agents. They write nothing, but one call can start a
 * whole tree that spends tokens on its own, and a child has no approval channel
 * to ask again — so delegation is where the fan-out has to stop.
 */
const DELEGATION_TOOLS = new Set(['subagent', 'subagent_fork', 'workflow', 'spawn_teammate'])

/** One-line summary of what a delegation call is about to start. */
function delegationSummary(name, args) {
  if (args === null || typeof args !== 'object') return ''
  if (name === 'workflow') {
    const meta = args.meta !== null && typeof args.meta === 'object' ? args.meta : {}
    const label = typeof meta.name === 'string' ? meta.name : ''
    const script = typeof args.script === 'string' ? args.script : ''
    const spawns = (script.match(/\bagent\s*\(/g) ?? []).length
    const parts = []
    if (label !== '') parts.push(label)
    if (spawns > 0) parts.push(`${spawns} agent() call(s)`)
    else if (script !== '') parts.push('script without agent() calls')
    return parts.join(' · ')
  }
  const text = typeof args.description === 'string' ? args.description
    : typeof args.prompt === 'string' ? args.prompt
      : typeof args.task === 'string' ? args.task : ''
  return short(text, 120)
}

/**
 * In-workspace locations that stay gated even when `gateWrites: "workspace"`
 * freely allows ordinary workspace writes: git hooks and dotfiles execute
 * later, and `node_modules/.bin` launchers are run by name.
 */
export const DEFAULT_PROTECTED_PATTERNS = Object.freeze([
  '**/.git/**',
  '**/.dsh/**',
  '**/node_modules/.bin/**',
  '**/.github/workflows/**',
])

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

/**
 * Files that change how other programs behave: shell startup scripts, git
 * hooks, editor task files, agent instruction files, and environment or
 * package-manager configuration. Writing one grants influence far beyond a
 * single edit — a shell profile runs at the next login, a git hook at the next
 * commit — so these are high risk rather than ordinary writes.
 */
export const DEFAULT_CONFIG_PATTERNS = Object.freeze([
  '**/.bashrc',
  '**/.bash_profile',
  '**/.bash_login',
  '**/.profile',
  '**/.zshrc',
  '**/.zshenv',
  '**/.zprofile',
  '**/.config/fish/config.fish',
  '**/Microsoft.PowerShell_profile.ps1',
  '**/Microsoft.VSCode_profile.ps1',
  '**/profile.ps1',
  '**/.git/hooks/**',
  '**/.git/config',
  '**/.gitmodules',
  '**/.vscode/tasks.json',
  '**/.vscode/launch.json',
  '**/.vscode/settings.json',
  '**/.vscode/mcp.json',
  '**/.idea/runConfigurations/**',
  '**/.mcp.json',
  '**/.cursor/mcp.json',
  '**/AGENTS.md',
  '**/CLAUDE.md',
  '**/.cursorrules',
  '**/.github/copilot-instructions.md',
  '**/.dsh-prompts/**',
  '**/.config',
  '**/.config/**',
  '**/*.config',
  '**/.env',
  '**/.env.*',
  '**/*.env',
  '**/.npmrc',
  '**/.yarnrc',
  '**/.yarnrc.yml',
  '**/pip.conf',
  '**/cordis.patch.yml',
  '**/cordis.yml',
])

/** The same targets as they appear in a shell command line. */
const CONFIG_TEXT = /(?:^|[\s"'`(=:,\\/])(?:\.bashrc|\.bash_profile|\.bash_login|\.zshrc|\.zshenv|\.zprofile|config\.fish|Microsoft\.(?:PowerShell|VSCode)_profile\.ps1|profile\.ps1|\.git[\/\\]hooks[\/\\][^\s"'`;|&<>]*|\.git[\/\\]config|\.gitmodules|\.vscode[\/\\](?:tasks|launch|settings|mcp)\.json|\.mcp\.json|AGENTS\.md|CLAUDE\.md|\.cursorrules|\.dsh-prompts|\.config(?:[\/\\][^\s"'`;|&<>]*)?|\.env(?:\.[\w.-]+)?|\.npmrc|\.yarnrc|pip\.conf|cordis(?:\.patch)?\.yml|\$(?:env:)?profile)(?=$|[\s"'`;|&<>),])/i

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
  restore: '删除备份或还原点 (delete backups or restore points)',
  account: '本地账户或管理员组变更 (local account or group change)',
  persist: '注册持久化项 (scheduled task, service or autostart)',
  defense: '关闭或放宽安全防线 (disable or widen a security control)',
  system: '系统配置修改 (system configuration)',
  perm: '权限/所有权修改 (permissions or ownership)',
  download: '下载并直接执行 (download and execute)',
})

/**
 * Why a high-risk label matters, shown verbatim in the approval card.
 *
 * A second confirmation is only worth a click if the card says what cannot be
 * undone: "system configuration" tells nobody anything, "this deletes the
 * restore points you would roll back to" does.
 */
const HIGH_RISK_EXPLAIN = Object.freeze({
  disk: {
    en: 'It rewrites or wipes a disk or volume; the data on it cannot be recovered from the file system afterwards.',
    zh: '会改写或清空磁盘/卷，之后无法从文件系统里恢复。',
  },
  delete: {
    en: 'A recursive or wildcard delete skips the recycle bin, so there is nothing left to restore from.',
    zh: '递归或通配删除不经过回收站，删掉就没有可还原的来源。',
  },
  restore: {
    en: 'It deletes the backups or restore points that would be used to undo a bad change.',
    zh: '会删掉系统还原点或备份——出事时正是靠它们回滚，删了就没了。',
  },
  account: {
    en: 'It creates or changes a local account or an administrator group. There is no undo; the old values have to be re-entered by hand.',
    zh: '会新增或修改本地账户/管理员组成员，没有撤销动作，只能凭记忆改回去。',
  },
  persist: {
    en: 'It registers something that runs again after a reboot: a scheduled task, a service, or an autostart entry.',
    zh: '会注册计划任务、服务或开机自启项——重启之后依然生效。',
  },
  defense: {
    en: 'It turns off or widens a security control such as Defender, the firewall, or volume encryption, and nothing restores it automatically.',
    zh: '会关闭或放宽 Defender、防火墙、卷加密这类防线，不会自己恢复。',
  },
  system: {
    en: 'It changes machine-wide configuration; the old value is rarely recorded anywhere.',
    zh: '会修改整机配置，旧值通常没有留底。',
  },
  perm: {
    en: 'It rewrites permissions or ownership; the previous ACL is not kept anywhere.',
    zh: '会改写权限/所有者，原 ACL 不会留底。',
  },
  download: {
    en: 'It downloads code and runs it in one step, so you only see the URL, never the payload.',
    zh: '下载与执行在同一步完成，你只能看到 URL，看不到真正跑的代码。',
  },
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
  ['disk', /\bformat-volume\b/i],
  ['disk', /\bdd\s+if=/i],
  ['disk', /\bcipher(?:\.exe)?\b[^\n]*\/w\b/i],
  ['delete', /\b(?:remove-item|ri)\b[^\n]*\s-(?:recurse|r)\b/i],
  ['delete', /\b(?:remove-item|ri)\b[^\n]*\s\*(?:\s|$)/i],
  ['delete', /\brm\b[^\n]*\s-[a-z]*r[a-z]*\b/i],
  ['delete', /\b(?:rd|rmdir)\b[^\n]*\/s\b/i],
  ['delete', /\b(?:del|erase)\b[^\n]*\/(?:[a-z]*[fs])/i],
  ['delete', /\b(?:del|erase)\b[^\n]*\*\.\*/i],
  // Destroying the ability to undo a change: backups, restore points, catalog.
  ['restore', /\bvssadmin(?:\.exe)?\b[^\n]*\bdelete\b[^\n]*\bshadows\b/i],
  ['restore', /\bwbadmin(?:\.exe)?\b[^\n]*\bdelete\b/i],
  ['restore', /\b(?:remove-computerrestorepoint|disable-computerrestore)\b/i],
  // Local accounts and administrator groups: no undo, only a manual reverse edit.
  ['account', /\b(?:new|set|remove|enable|disable|rename)-localuser\b/i],
  ['account', /\b(?:add|remove)-localgroupmember\b/i],
  ['account', /\bnet(?:\.exe)?\s+(?:user|localgroup)\b[^\n]*\/add\b/i],
  // Persistence that survives a reboot.
  ['persist', /\b(?:register|new|set)-scheduledtask(?:action|trigger|principal|settings)?\b/i],
  ['persist', /\bschtasks\b[^\n]*\/(?:change|delete)\b/i],
  ['persist', /\b(?:new|set)-itemproperty\b[^\n]*\bcurrentversion\\run\b/i],
  ['persist', /\bremove-service\b/i],
  // Turning a security control off, or wider than it was.
  ['defense', /\b(?:set|add)-mppreference\b/i],
  ['defense', /\bnew-netfirewallrule\b|\bset-netfirewallprofile\b[^\n]*-enabled\s+\$?false\b/i],
  ['defense', /\bmanage-bde\b[^\n]*-(?:off|on|pause|resume|protect|unprotect|change|disable|set)\b/i],
  ['defense', /\b(?:enable|disable|suspend)-bitlocker\b/i],
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
  // Download-and-execute in one line: the user sees a URL, not the payload.
  ['download', /\b(?:curl|wget|invoke-webrequest|iwr|irm|invoke-restmethod)\b[^\n]*\|\s*(?:iex|invoke-expression|bash|sh|zsh|pwsh|powershell)\b/i],
  ['download', /\b(?:iex|invoke-expression)\b[\s\S]*\b(?:downloadstring|downloadfile|invoke-webrequest|iwr|irm)\b/i],
])

/** Commands that only read, so a plain invocation needs no approval. */
const READ_ONLY_COMMANDS = new Set([
  'ls', 'dir', 'get-childitem', 'gci', 'pwd', 'get-location', 'gl', 'cd', 'set-location',
  'push-location', 'pop-location', 'cat', 'type', 'get-content', 'gc', 'more', 'less',
  'head', 'tail', 'grep', 'rg', 'findstr', 'select-string', 'sls', 'get-item', 'gi',
  'test-path', 'resolve-path', 'split-path', 'join-path', 'measure', 'measure-object',
  'select-object', 'select', 'where-object', 'foreach-object', 'sort', 'sort-object', 'group-object',
  'format-table', 'ft', 'format-list', 'fl', 'convertto-json', 'convertto-csv',
  'get-command', 'gcm', 'get-help', 'help', 'man', 'get-process', 'ps', 'tasklist',
  'get-service', 'whoami', 'hostname', 'id', 'uname', 'ipconfig', 'netstat',
  'systeminfo', 'ver', 'where', 'which', 'echo', 'write-output', 'write-host',
  'out-null', 'get-date', 'date', 'printenv', 'env', 'tree', 'wc', 'du', 'df',
  'stat', 'file', 'cmp', 'diff', 'comm', 'basename', 'dirname', 'realpath',
  // Read-only cmdlets that were missing: registry and property reads, display
  // writers, JSON/CSV conversion, and sleep/progress helpers. Without these,
  // every `Get-ItemProperty` or `Out-String` turned a read into "may write".
  'out-string', 'out-host', 'convertfrom-json', 'convertfrom-csv',
  'get-itemproperty', 'get-itempropertyvalue', 'get-member', 'get-unique',
  'compare-object', 'format-wide', 'format-custom', 'measure-command',
  'start-sleep', 'get-psdrive', 'get-volume', 'get-acl',
  'write-progress', 'write-verbose', 'write-information', 'get-history',
  'test-connection', 'resolve-dnsname', 'get-ciminstance', 'get-wmiobject',
  'get-eventlog', 'get-winevent',
  // More read-only cmdlets: hashing, XML/StringData parsing, and diagnostics.
  'get-filehash', 'select-xml', 'convertfrom-stringdata', 'get-random',
  'get-culture', 'get-host', 'test-netconnection', 'out-gridview',
  // Discovery and status cmdlets: they read state and never write it.
  'get-alias', 'gal', 'get-module', 'gmo', 'get-variable', 'gv', 'get-verb',
  'get-uiculture', 'get-timezone', 'get-hotfix', 'get-computerinfo',
  'get-cimclass', 'get-psprovider', 'get-executionpolicy', 'get-uptime',
  'get-mpcomputerstatus', 'get-netadapter', 'get-netipaddress', 'get-netroute',
  'get-dnsclientcache', 'get-nettcpconnection',
  // Read-only output and input helpers.
  'read-host', 'convertto-html', 'out-default', 'out-host', 'oh', 'cls',
  'history', 'test-json',
  // Common aliases for the cmdlets above or already in this list.
  'gm', 'gp', 'gps', 'gsv', 'gdr', 'gu', 'fw', 'fc', 'ogv', 'sleep',
  'group', 'compare',
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

/**
 * The object every classifier returns.
 *
 *   kind   what the call does: `write`, `shell-write`, `config-write`,
 *          `deferred-action`, `sensitive-read`, or `unclassified` when
 *          classification failed;
 *   risk   `normal` or `high`; `high` activates the second confirmation;
 *   reason one English line naming the path or command; shown in the dialog
 *          and written to the decision log;
 *   displayReason the same text in every locale.
 */
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
  for (let guard = 0; guard < 4; guard += 1) {
    if (text === '') return ''
    text = text.replace(/^[&(]\s*/, '')
    const assignment = /^[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+/.exec(text)
    if (assignment !== null) text = text.slice(assignment[0].length)
    const quoted = /^["']([^"']*)["']/.exec(text)
    if (quoted === null) break
    const rest = text.slice(quoted[0].length).trimStart()
    // `"literal" + expression` is an expression, not a command word.
    if (!rest.startsWith('+')) return quoted[1].toLowerCase()
    text = rest.slice(1).trimStart()
  }
  const match = /^(\S+)/.exec(text)
  return match === null ? '' : match[1].replace(/^["']|["']$/g, '').toLowerCase()
}

/** Drop the directory and a script suffix: `C:\\Program Files\\x\\Git.EXE` → `git`. */
function commandName(token) {
  const trimmed = token.replace(/[\\/]+$/, '')
  return path.basename(trimmed).replace(/\.(?:exe|cmd|bat|com|ps1|sh)$/i, '').toLowerCase()
}

/** Git options that consume the next token, so it is not the subcommand (`-C <path>`). */
const GIT_VALUE_OPTIONS = new Set(['-c', '-C', '--git-dir', '--work-tree', '--namespace', '--exec-path'])

function gitVerdict(segment) {
  const words = segment.trim().split(/\s+/).slice(1)
  let subcommand = ''
  for (let index = 0; index < words.length; index += 1) {
    const word = words[index]
    if (word.startsWith('-')) {
      if (GIT_VALUE_OPTIONS.has(word)) index += 1
      continue
    }
    subcommand = word.toLowerCase()
    break
  }
  if (subcommand === '') return 'read'
  if (GIT_READ_SUBCOMMANDS.has(subcommand)) return 'read'
  // `git remote -v` / `git remote show` only read; add/remove/set-url/prune write.
  if (subcommand === 'remote') return /(?:^|\s)(?:-v|--verbose|show)\b/.test(segment) ? 'read' : 'write'
  if (subcommand !== 'config') return 'write'
  // `git config --get <key>` only reads; every other config call may write.
  return segment.includes('--get') ? 'read' : 'write'
}

/** Shell containers whose body runs (or is scanned) as commands of its own. */
const CONTAINER_COMMANDS = new Set([
  'if', 'elseif', 'else', 'foreach', 'for', 'while', 'do', 'until', 'switch',
  'try', 'catch', 'finally', 'function', 'filter', 'begin', 'process', 'end',
])

/**
 * Cmdlets whose `{ … }` is a statement block: the block decides the verdict.
 * `select-object` / `sort-object` stay out on purpose — their `{ … }` is a
 * property expression (often `@{n=…;e={…}}`), not a place to run commands.
 */
const BLOCK_COMMANDS = new Set(['foreach-object', 'where-object'])

/** PowerShell aliases that name a block cmdlet. */
const BLOCK_ALIASES = new Map([['%', 'foreach-object'], ['?', 'where-object']])

/** Top-level `{ … }` bodies of one segment, in source order. */
function blockBodies(segment) {
  const bodies = []
  let depth = 0
  let start = -1
  let quote = ''
  for (let index = 0; index < segment.length; index += 1) {
    const char = segment[index]
    if (quote !== '') {
      if (char === '`') { index += 1; continue }
      if (char === quote) quote = ''
      continue
    }
    if (char === "'" || char === '"') { quote = char; continue }
    if (char === '{') {
      if (depth === 0) start = index + 1
      depth += 1
      continue
    }
    if (char === '}') {
      depth = Math.max(0, depth - 1)
      if (depth === 0 && start >= 0) {
        bodies.push(segment.slice(start, index))
        start = -1
      }
    }
  }
  return bodies
}

/**
 * Split on newlines and the shell operators `;`, `&&`, `||` and `|`, but only
 * at the top level: a separator inside quotes, `( … )`, `[ … ]` or `{ … }`
 * belongs to the expression it sits in. Splitting inside a block used to turn
 * `foreach`, bare strings and assignments into fake commands.
 */
function commandSegments(command) {
  const segments = []
  let buffer = ''
  let quote = ''
  let depth = 0
  const flush = () => {
    const trimmed = buffer.trim()
    if (trimmed !== '') segments.push(trimmed)
    buffer = ''
  }
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index]
    if (quote !== '') {
      buffer += char
      if (char === '`' && quote === '"') { buffer += command[index + 1] ?? ''; index += 1; continue }
      if (char === quote) quote = ''
      continue
    }
    // Here-string: skip to its closing marker so its body is never parsed.
    if (char === '@' && (command[index + 1] === "'" || command[index + 1] === '"')) {
      const closer = command[index + 1] === "'" ? "'@" : '"@'
      const end = command.indexOf(`\n${closer}`, index + 2)
      const stop = end === -1 ? command.length : end + 3
      buffer += command.slice(index, stop)
      index = stop - 1
      continue
    }
    if (char === "'" || char === '"') { quote = char; buffer += char; continue }
    if (char === '`') { buffer += char + (command[index + 1] ?? ''); index += 1; continue }
    if (char === '(' || char === '[' || char === '{') { depth += 1; buffer += char; continue }
    if (char === ')' || char === ']' || char === '}') { depth = Math.max(0, depth - 1); buffer += char; continue }
    if (depth === 0 && (char === ';' || char === '\n')) { flush(); continue }
    if (depth === 0 && char === '|') { flush(); if (command[index + 1] === '|') index += 1; continue }
    if (depth === 0 && char === '&' && command[index + 1] === '&') { flush(); index += 1; continue }
    buffer += char
  }
  flush()
  return segments
}

/** Index of the `)` closing the `(` at `openIndex`, or -1 when unbalanced. */
function matchingParen(text, openIndex) {
  let depth = 0
  let quote = ''
  for (let index = openIndex; index < text.length; index += 1) {
    const char = text[index]
    if (quote !== '') {
      if (char === '`') { index += 1; continue }
      if (char === quote) quote = ''
      continue
    }
    if (char === "'" || char === '"') { quote = char; continue }
    if (char === '(') { depth += 1; continue }
    if (char === ')') {
      depth -= 1
      if (depth === 0) return index
    }
  }
  return -1
}

/** Text after a container header: `if (cond) <rest>`, `else <rest>`. */
function afterHeader(text) {
  const open = text.indexOf('(')
  if (open === -1) {
    const space = text.indexOf(' ')
    return space === -1 ? null : text.slice(space + 1)
  }
  const close = matchingParen(text, open)
  return close === -1 ? null : text.slice(close + 1)
}

/**
 * False when quotes, `( … )`, `[ … ]` or `{ … }` do not close. A command the
 * splitter cannot fully read is judged as a write: ambiguity must not fail open.
 */
function isBalanced(command) {
  let quote = ''
  let depth = 0
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index]
    if (quote !== '') {
      if (char === '`' && quote === '"') { index += 1; continue }
      if (char === quote) quote = ''
      continue
    }
    if (char === '@' && (command[index + 1] === "'" || command[index + 1] === '"')) {
      const closer = command[index + 1] === "'" ? "'@" : '"@'
      const end = command.indexOf(`\n${closer}`, index + 2)
      if (end === -1) return false
      index = end + 2
      continue
    }
    if (char === "'" || char === '"') { quote = char; continue }
    if (char === '`') { index += 1; continue }
    if (char === '(' || char === '[' || char === '{') { depth += 1; continue }
    if (char === ')' || char === ']' || char === '}') {
      depth -= 1
      if (depth < 0) return false
    }
  }
  return quote === '' && depth === 0
}

/** Scan one expandable string body for `$( … )` substitutions. */
function scanExpandable(body, bodies) {
  let index = 0
  while (index < body.length) {
    if (body[index] === '`') { index += 2; continue }
    if (body[index] === '$' && body[index + 1] === '(') {
      const close = matchingParen(body, index + 1)
      if (close === -1) return
      bodies.push(body.slice(index + 2, close))
      index = close + 1
      continue
    }
    index += 1
  }
}

/**
 * `$( … )` bodies found outside single quotes. A single-quoted string is a
 * literal, but a double-quoted one still executes its substitutions. The same
 * split applies to here-strings: `@" … "@` expands, `@' … '@` does not.
 */
function collectSubexpressions(command) {
  const bodies = []
  let index = 0
  while (index < command.length) {
    const char = command[index]
    if (char === '@' && (command[index + 1] === "'" || command[index + 1] === '"')) {
      const closer = command[index + 1] === "'" ? "'@" : '"@'
      const end = command.indexOf(`\n${closer}`, index + 2)
      if (end === -1) return bodies
      if (command[index + 1] === '"') scanExpandable(command.slice(index + 2, end), bodies)
      index = end + 3
      continue
    }
    if (char === "'") {
      index += 1
      while (index < command.length) {
        if (command[index] === "'") {
          if (command[index + 1] === "'") { index += 2; continue }
          break
        }
        index += 1
      }
      index += 1
      continue
    }
    if (char === '"') {
      index += 1
      while (index < command.length) {
        if (command[index] === '`') { index += 2; continue }
        if (command[index] === '"') { index += 1; break }
        if (command[index] === '$' && command[index + 1] === '(') {
          const close = matchingParen(command, index + 1)
          if (close === -1) return bodies
          bodies.push(command.slice(index + 2, close))
          index = close + 1
          continue
        }
        index += 1
      }
      continue
    }
    if (char === '`') { index += 2; continue }
    if (char === '$' && command[index + 1] === '(') {
      const close = matchingParen(command, index + 1)
      if (close === -1) return bodies
      bodies.push(command.slice(index + 2, close))
      index = close + 1
      continue
    }
    index += 1
  }
  return bodies
}

/** `write` when the text or any of its `$( … )` substitutions writes. */
function writesIn(text, shellMode, depth = 0) {
  if (depth > 8) return true
  if (verdictOf(text, shellMode, depth) === 'write') return true
  for (const body of collectSubexpressions(text)) {
    if (body.trim() !== '' && writesIn(body, shellMode, depth + 1)) return true
  }
  return false
}

/**
 * `read` when the segment certainly only reads, otherwise `write`.
 *
 * Container keywords (`if`, `foreach`, `function`, …) and variable assignments
 * are peeled first so their bodies and right-hand sides are judged as the
 * commands they are. Unknown commands still count as writes unless the shell
 * mode is `lenient`.
 */
function commandVerdict(segment, shellMode, depth = 0) {
  const trimmed = segment.trim()
  if (trimmed === '') return 'read'
  if (depth > 8) return 'write'

  // A bare string expression only prints.
  if (/^["']/.test(trimmed)) return 'read'

  // `$x = <expr>`: judge the right-hand side, not the assignment.
  const assignment = /^\$[A-Za-z_][A-Za-z0-9_:]*\s*=\s*([\s\S]*)$/.exec(trimmed)
  if (assignment !== null) {
    const rhs = assignment[1].trim()
    return rhs === '' ? 'read' : verdictOf(rhs, shellMode, depth + 1)
  }

  // `$( … )` runs the commands inside: it is a command context, not a value.
  if (trimmed.startsWith('$(')) {
    const close = matchingParen(trimmed, 1)
    if (close === -1) return 'write'
    const body = trimmed.slice(2, close)
    if (body.trim() !== '' && writesIn(body, shellMode, depth + 1)) return 'write'
    // A member access after the sub-expression (`.Length`, `[0]`) is a value.
    const tail = trimmed.slice(close + 1).trim()
    return tail === '' || tail.startsWith('.') || tail.startsWith('[') ? 'read' : 'write'
  }

  // A here-string statement is a value, never a command name. The expandable
  // form is still scanned for `$( … )` by writesIn().
  if (trimmed.startsWith("@'") || trimmed.startsWith('@"')) return 'read'

  // Any other variable-led expression is a value (`.Replace(…)`, `[0]`, …).
  if (trimmed.startsWith('$')) return 'read'

  // Numeric and operator-led literals are values, not command names.
  if (/^[0-9]/.test(trimmed)) return 'read'
  if (/^[-!+,]/.test(trimmed)) return 'read'

  // `( … )` is a sub-expression: judge what it contains, then decide whether
  // the tail is a value access. Only property/index chains count, so
  // `(Get-Item x).Delete()` still fails closed.
  if (trimmed.startsWith('(')) {
    const close = matchingParen(trimmed, 0)
    if (close === -1) return 'write'
    const body = trimmed.slice(1, close)
    if (body.trim() !== '' && verdictOf(body, shellMode, depth + 1) === 'write') return 'write'
    const tail = trimmed.slice(close + 1).trim()
    return tail === '' || /^(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d*\])+$/.test(tail) ? 'read' : 'write'
  }

  // `@( … )` is an array literal whose elements are expressions of their own.
  if (trimmed.startsWith('@(')) {
    const close = trimmed.lastIndexOf(')')
    const body = close === -1 ? trimmed.slice(2) : trimmed.slice(2, close)
    return body.trim() === '' ? 'read' : verdictOf(body, shellMode, depth + 1)
  }
  // `@{ … }` is a hash literal: keys and values only.
  if (trimmed.startsWith('@{')) return 'read'

  // `[Type]::Method(…)`: only pure helper types are values.
  const staticCall = /^\[([A-Za-z_][A-Za-z0-9_.]*)\]\s*::\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(trimmed)
  if (staticCall !== null) {
    const type = staticCall[1].toLowerCase().split('.').pop()
    if (READ_ONLY_STATICS.has(type)) return 'read'
    // A read-only method on an otherwise write-capable type: `File.OpenRead`
    // must not be judged like `File.WriteAllText`.
    return READ_ONLY_STATICS_METHODS.has(`${type}.${staticCall[2].toLowerCase()}`) ? 'read' : 'write'
  }

  const token = firstToken(trimmed)
  if (token === '') return 'read'
  const rawName = commandName(token)
  const name = BLOCK_ALIASES.get(rawName) ?? rawName

  if (BLOCK_COMMANDS.has(name)) {
    const bodies = blockBodies(trimmed)
    if (bodies.length === 0) {
      // `ForEach-Object Name` / `Where-Object PSIsContainer` pass a property
      // name, not a script block: there is no inner command to judge, so the
      // segment is just the cmdlet call. A bare `$variable` after the cmdlet is
      // an opaque script block and still fails closed.
      const rest = trimmed.replace(/^\S+\s*/, '').replace(/^(?:-[A-Za-z]+\s*)+/, '')
      if (rest.startsWith('$')) return 'write'
      return READ_ONLY_COMMANDS.has(name) ? 'read' : 'write'
    }
    if (bodies.some(body => verdictOf(body, shellMode, depth + 1) === 'write')) return 'write'
    // Anything after the last block is another statement of the same segment.
    const last = trimmed.lastIndexOf('}')
    const tail = last === -1 ? '' : trimmed.slice(last + 1).trim()
    return tail === '' ? 'read' : verdictOf(tail, shellMode, depth + 1)
  }

  if (CONTAINER_COMMANDS.has(name)) {
    const bodies = blockBodies(trimmed)
    if (bodies.length > 0) {
      if (bodies.some(body => verdictOf(body, shellMode, depth + 1) === 'write')) return 'write'
      // Anything after the last block is another statement of the same segment.
      const last = trimmed.lastIndexOf('}')
      const tail = last === -1 ? '' : trimmed.slice(last + 1).trim()
      return tail === '' ? 'read' : verdictOf(tail, shellMode, depth + 1)
    }
    // PowerShell allows `if (cond) <statement>` and `foreach (…) <command>`
    // without braces, so judge what follows the header instead of assuming an
    // empty body.
    const rest = afterHeader(trimmed)
    if (rest === null) return 'write'
    return rest.trim() === '' ? 'read' : verdictOf(rest, shellMode, depth + 1)
  }

  if (READ_ONLY_COMMANDS.has(name)) return 'read'
  if (name === 'git') return gitVerdict(trimmed)
  // `node --check x.mjs` only parses the file. A bare `node x.mjs`, `node --test`
  // or `node -e …` runs project code, so it stays a write.
  if (name === 'node') {
    if (/(?:^|\s)(?:--check|-c)(?:\s|$)/.test(trimmed)) return 'read'
    return shellMode === 'lenient' ? 'read' : 'write'
  }
  // `sed -i` / `perl -i` edit files in place; without the flag they only read.
  if (name === 'sed' || name === 'perl') return /(?:^|\s)-\w*i/.test(trimmed) ? 'write' : 'read'
  if (WRITE_COMMANDS.has(name)) return 'write'
  return shellMode === 'lenient' ? 'read' : 'write'
}

/** `write` when any segment of `text` writes. */
function verdictOf(text, shellMode, depth = 0) {
  return commandSegments(text).some(segment => commandVerdict(segment, shellMode, depth) === 'write') ? 'write' : 'read'
}

/** First pattern that matches, in HIGH_RISK_PATTERNS order, or null. */
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
    const why = HIGH_RISK_EXPLAIN[highRisk.id]
    return decision(
      'destructive',
      'high',
      `High-risk command (${label}).${why === undefined ? '' : ` ${why.en}`} Command: ${short(text)}`,
      `高危：命中「${label}」。${why === undefined ? '' : `风险：${why.zh}`}\n将执行：${short(text)}`,
    )
  }

  const tokens = collectAbsoluteTokens(text)
  const systemToken = tokens.find(token => isSystemPath(token, systemRoots)) ?? null
  const writes = !isBalanced(text) || REDIRECT.test(text) || writesIn(text, shellMode)

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
    const configHit = commandSegments(text).some(segment => {
      if (!CONFIG_TEXT.test(segment)) return false
      // Mentioning a path is not writing it: require a write verb or a redirect
      // in the same segment.
      return REDIRECT.test(segment) || writesIn(segment, shellMode)
    })
    if (configHit) {
      return decision(
        'config-write',
        'high',
        `High-risk command writing a configuration or behavior file: ${short(text)}`,
        `高危：命令将写入配置/行为文件：${short(text)}`,
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

function classifyWrite(tool, value, cwd, { systemRoots, sensitivePatterns, exemptPaths, configPatterns, protectedPatterns = [] }) {
  const target = value.trim()
  const absolute = absoluteOf(target, cwd)
  const real = absolute === null ? null : realpathDeep(absolute)
  // Placement decides `gateWrites: "workspace"`: inside the session directory
  // and outside the protected list. An unresolvable path counts as outside.
  const inWorkspace = absolute !== null
    && typeof cwd === 'string'
    && cwd.trim() !== ''
    && isInside(cwd, absolute)
    && matchSensitiveAny([absolute, real, target], protectedPatterns) === null

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

  if (matchSensitiveAny([absolute, real, target], configPatterns) !== null) {
    return decision(
      'config-write',
      'high',
      `High-risk write to a configuration or behavior file: ${short(absolute ?? target)}`,
      `高危：将写入配置/行为文件：${short(absolute ?? target)}`,
    )
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
  return {
    ...decision(
      'write',
      'normal',
      `Approval required before writing: ${short(absolute ?? target)}`,
      `写操作需要审批：${short(absolute ?? target)}`,
    ),
    inWorkspace,
  }
}

/** Classify every target of one call; the highest risk wins. */
function classifyWriteMany(tool, values, cwd, options) {
  let worst = null
  let outside = false
  for (const value of values) {
    const candidate = classifyWrite(tool, value, cwd, options)
    if (candidate === null) continue
    // One target outside the workspace keeps the whole call outside: a multi-file
    // edit must not ride on the placement of its first file.
    if (candidate.inWorkspace !== true) outside = true
    if (worst === null || (worst.risk !== 'high' && candidate.risk === 'high')) worst = candidate
  }
  if (worst === null) return null
  const placed = { ...worst, inWorkspace: worst.inWorkspace === true && !outside }
  if (values.length < 2) return placed
  return {
    ...placed,
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
  const configPatterns = [
    ...DEFAULT_CONFIG_PATTERNS,
    ...(Array.isArray(config.extraConfigPaths) ? config.extraConfigPaths : []),
  ]
  const protectedPatterns = Array.isArray(config.protectedPaths)
    ? config.protectedPaths
    : DEFAULT_PROTECTED_PATTERNS
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
    const decision = classifyWriteMany(name, values, cwd, { systemRoots, sensitivePatterns, exemptPaths, configPatterns, protectedPatterns })
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

  // Autonomy travels through tools, not shells: these keep working after the
  // user leaves, so `gateShell` does not apply. `update_goal` is split by
  // action because finishing a goal removes autonomy instead of granting it.
  if (name === 'update_goal') {
    const action = args !== null && typeof args === 'object' ? args.action : undefined
    if (!AUTONOMY_GOAL_ACTIONS.has(action)) return null
    return decision(
      'deferred-action',
      'high',
      `Approval required before granting autonomous work (update_goal:${action}): ${autonomySummary(name, args)}`,
      `自主性操作需要审批（update_goal:${action}）：${autonomySummary(name, args)}`,
    )
  }

  if (AUTONOMY_TOOLS.has(name)) {
    return decision(
      'deferred-action',
      'high',
      `Approval required before granting autonomous work (${name}): ${autonomySummary(name, args)}`,
      `自主性操作需要审批（${name}）：${autonomySummary(name, args)}`,
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

  if (config.gateDelegation !== false && DELEGATION_TOOLS.has(name)) {
    const detail = delegationSummary(name, args)
    return decision(
      'delegation',
      'normal',
      `Approval required before starting more agents (${name})${detail === '' ? '' : `: ${detail}`}`,
      `委派子代理需要审批（${name}）${detail === '' ? '' : `：${detail}`}`,
    )
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

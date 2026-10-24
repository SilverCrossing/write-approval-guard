/**
 * write-approval-guard — every write-type file operation needs approval, even
 * inside the session workspace, and destructive or system-level operations
 * need a second, separate confirmation. Reading secret-bearing configuration
 * files needs approval as well.
 *
 * It sits on the `tools/pre-execute` waterfall (before dispatch) and returns
 * one of three decisions:
 *
 *   - `ask`  → the ordinary approval dialog;
 *   - `deny` → the request was refused, or no approval channel exists;
 *   - `next` → the call is not gated.
 *
 * High-risk calls are confirmed twice: this plugin asks through the approval
 * service first (1/2), and the ordinary approval that follows is the second
 * dialog (2/2). Both must be approved.
 *
 * `onReject` decides what a rejection means: `call` (default) rejects just that
 * call and lets the runtime report it; `turn` makes the plugin own the ordinary
 * approval too, so a rejection also stops the current turn cooperatively
 * (`agent.cancel()`) and the model waits for the user's next instruction.
 *
 * The mode can be changed in the profile patch (`mode:`) or, while the process
 * runs, through the human-only command `/write-guard on|off|status`. Slash
 * commands cannot be issued by the model, so the runtime switch cannot be used
 * to widen its own access.
 */
import {
  classifyToolCall,
  DEFAULT_SENSITIVE_PATTERNS,
} from './classify.js'

export const name = 'write-approval-guard'

/** `tools` is the only hard dependency; `approval` and `commands` are optional. */
export const inject = ['tools']

const MODES = new Set(['enforce', 'off'])
const DEFAULT_MODE = 'enforce'
const ON_REJECT = new Set(['call', 'turn'])

function warn(message) {
  console.warn(`[write-approval-guard] ${message}`)
}

/** Read a list of non-empty strings, warning instead of silently falling back. */
function stringList(value, key, fallback) {
  if (value === undefined) return [...fallback]
  if (!Array.isArray(value)) {
    warn(`config.${key} must be an array of strings; keeping the default`)
    return [...fallback]
  }
  const list = value
    .filter(entry => typeof entry === 'string' && entry.trim() !== '')
    .map(entry => entry.trim())
  if (list.length !== value.length) {
    warn(`config.${key} ignored ${value.length - list.length} non-string or empty entries`)
  }
  return list
}

function normalizeConfig(raw) {
  const config = raw !== null && typeof raw === 'object' ? raw : {}
  const mode = MODES.has(config.mode) ? config.mode : DEFAULT_MODE
  if (config.mode !== undefined && !MODES.has(config.mode)) {
    warn(`config.mode must be "enforce" or "off"; keeping "${DEFAULT_MODE}"`)
  }
  const highRiskConfirmations = config.highRiskConfirmations === 'single' ? 'single' : 'double'
  if (config.highRiskConfirmations !== undefined && !['double', 'single'].includes(config.highRiskConfirmations)) {
    warn('config.highRiskConfirmations must be "double" or "single"; keeping "double"')
  }
  const sensitiveReadConfirmations = config.sensitiveReadConfirmations === 'double' ? 'double' : 'single'
  if (config.sensitiveReadConfirmations !== undefined && !['double', 'single'].includes(config.sensitiveReadConfirmations)) {
    warn('config.sensitiveReadConfirmations must be "single" or "double"; keeping "single"')
  }
  const shellMode = ['conservative', 'lenient', 'off'].includes(config.shellMode)
    ? config.shellMode
    : 'conservative'
  if (config.shellMode !== undefined && !['conservative', 'lenient', 'off'].includes(config.shellMode)) {
    warn('config.shellMode must be "conservative", "lenient" or "off"; keeping "conservative"')
  }
  const onReject = ON_REJECT.has(config.onReject) ? config.onReject : 'call'
  if (config.onReject !== undefined && !ON_REJECT.has(config.onReject)) {
    warn('config.onReject must be "call" or "turn"; keeping "call"')
  }
  const unknownTools = config.unknownTools === 'ask' ? 'ask' : 'allow'
  if (config.unknownTools !== undefined && !['allow', 'ask'].includes(config.unknownTools)) {
    warn('config.unknownTools must be "allow" or "ask"; keeping "allow"')
  }
  const gateWrites = config.gateWrites === 'risky' ? 'risky' : 'all'
  if (config.gateWrites !== undefined && !['all', 'risky'].includes(config.gateWrites)) {
    warn('config.gateWrites must be "all" or "risky"; keeping "all"')
  }
  return {
    mode,
    onReject,
    unknownTools,
    gateWrites,
    highRiskConfirmations,
    sensitiveReadConfirmations,
    gateShell: config.gateShell !== false,
    shellMode,
    sensitivePaths: stringList(config.sensitivePaths, 'sensitivePaths', DEFAULT_SENSITIVE_PATTERNS),
    extraSystemRoots: stringList(config.extraSystemRoots, 'extraSystemRoots', []),
    exemptPaths: stringList(config.exemptPaths, 'exemptPaths', []),
    ignoreTools: stringList(config.ignoreTools, 'ignoreTools', []),
  }
}

/** Current session directory, or null when it cannot be determined. */
async function sessionCwd(ctx, exec) {
  const workingDirectory = ctx.get('workingDirectory')
  if (workingDirectory === undefined || typeof workingDirectory.ensure !== 'function') return null
  if (exec.agent === undefined) return null
  try {
    return await workingDirectory.ensure(exec.agent, exec.signal)
  } catch {
    return null
  }
}

/**
 * Cooperative stop of the current turn: `agent.cancel()` aborts the current
 * activity, clears pending work, and keeps already delivered stream text. It
 * does not kill a process or discard the session.
 */
function stopTurn(exec) {
  const agent = exec.agent
  if (agent === undefined || agent === null || typeof agent.cancel !== 'function') {
    warn('onReject is "turn" but the agent has no cancel(); the rejection only stops this call')
    return false
  }
  try {
    agent.cancel()
    return true
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    warn(`agent.cancel() failed: ${message}`)
    return false
  }
}

function denyDecision(decision, tag) {
  return {
    kind: 'deny',
    reason: `${decision.reason} [write-approval-guard: ${tag}]`,
    info: {
      name: 'WriteApprovalDenied',
      code: 'WRITE_APPROVAL_DENIED',
      reason: decision.displayReason.zh,
    },
  }
}

/** A rejection, optionally stopping the whole turn. */
function rejectionDecision(exec, decision, tag, config) {
  const stopped = config.onReject === 'turn' ? stopTurn(exec) : false
  const notice = stopped
    ? ' The user rejected this call and stopped the current turn; do not continue on your own — wait for their next instruction.'
    : ''
  return {
    kind: 'deny',
    reason: `${decision.reason} [write-approval-guard: ${tag}]${notice}`,
    info: {
      name: 'WriteApprovalDenied',
      code: 'WRITE_APPROVAL_DENIED',
      reason: stopped
        ? `${decision.displayReason.zh} 用户拒绝并停止了本轮，等待用户指示。`
        : decision.displayReason.zh,
    },
  }
}

/** Ask once through the approval service; returns a normalized outcome. */
async function requestDecision(ctx, exec, decision, override) {
  const approval = ctx.get('approval')
  if (approval === undefined || typeof approval.request !== 'function') {
    return { tag: 'approval-unavailable' }
  }
  if (exec.agent === undefined) return { tag: 'no-agent' }

  let outcome
  try {
    outcome = await approval.request({
      agent: exec.agent,
      toolName: exec.name,
      callId: exec.callId,
      reason: override !== undefined ? override.reason : decision.reason,
      displayReason: override !== undefined ? override.displayReason : decision.displayReason,
      signal: exec.signal,
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    warn(`approval request failed: ${message}`)
    return { tag: 'approval-failed' }
  }

  if (outcome === 'allowed-once') return { allowed: true }
  if (outcome === 'cancelled') return { cancelled: true }
  if (outcome === 'rejected') return { rejected: true }
  return { tag: `approval-${outcome}` }
}

/**
 * The first of two confirmations for a high-risk call. Returns null once it is
 * approved; otherwise an immediate deny/cancel decision.
 */
async function confirmHighRisk(ctx, exec, decision, config) {
  const outcome = await requestDecision(ctx, exec, decision, {
    reason: `High-risk file operation (confirmation 1/2): ${decision.reason}`,
    displayReason: {
      en: `Step 1 of 2 — high-risk file operation. ${decision.displayReason.en} Approving here only opens the ordinary approval for this single call.`,
      zh: `第 1/2 次确认——高危文件操作。${decision.displayReason.zh}此处批准只会再弹出这一次调用的常规审批，两次都批准才会执行。`,
    },
  })
  if (outcome.allowed === true) return null
  if (outcome.cancelled === true) return { kind: 'cancel' }
  if (outcome.rejected === true) return rejectionDecision(exec, decision, 'approval-rejected', config)
  return denyDecision(decision, outcome.tag)
}

function withSecondStep(decision) {
  return {
    reason: decision.reason,
    displayReason: {
      en: `Step 2 of 2 — ordinary approval. ${decision.displayReason.en}`,
      zh: `第 2/2 次确认——常规审批。${decision.displayReason.zh}`,
    },
  }
}

function usage() {
  return [
    '用法：/write-guard [status|on|off]',
    '  status — 显示当前模式与拦截规则',
    '  on     — 启用（默认）',
    '  off    — 临时关闭（重启后回到配置默认值）',
  ].join('\n')
}

function statusText(mode, config) {
  const high = config.highRiskConfirmations === 'double' ? '两次确认' : '仅一次确认'
  return [
    `写操作审批：${mode === 'enforce' ? '启用' : '已关闭'}（配置默认：${config.mode}）`,
    `写入门禁：${config.gateWrites === 'risky' ? '仅高风险' : '全部写入'}`,
    `拒绝行为：${config.onReject === 'turn' ? '拒绝并停止本轮' : '仅拒绝本次调用'}`,
    `未登记工具：${config.unknownTools === 'ask' ? '审批' : '放行'}`,
    `高危操作：${high}`,
    `敏感读取：${config.sensitiveReadConfirmations === 'double' ? '两次确认' : '一次确认'}`,
    `命令行：${config.gateShell ? `检查（${config.shellMode}）` : '不检查'}`,
    `敏感规则：${config.sensitivePaths.length} 条；额外系统路径：${config.extraSystemRoots.length} 条；豁免路径：${config.exemptPaths.length} 条`,
  ].join('\n')
}

function registerCommand(ctx, config, getMode, setMode) {
  const commands = ctx.get('commands')
  if (commands === undefined || typeof commands.register !== 'function') {
    warn('commands service unavailable; /write-guard is not registered')
    return
  }
  try {
    const definition = {
      name: 'write-guard',
      description: '查看或切换写操作审批：on（启用）、off（临时关闭）、status。',
      input: { hint: 'status | on | off' },
      handler: (invocation) => {
        const argument = invocation.rawInput.trim().toLowerCase()
        if (argument === '' || argument === 'status') {
          return { kind: 'success', text: statusText(getMode(), config) }
        }
        if (argument === 'on' || argument === 'enforce') {
          setMode('enforce')
          return { kind: 'success', text: `已启用写操作审批。\n${statusText('enforce', config)}` }
        }
        if (argument === 'off') {
          setMode('off')
          return { kind: 'success', text: `已临时关闭写操作审批（重启后恢复为 ${config.mode}）。` }
        }
        return { kind: 'error', text: usage() }
      },
    }
    if (typeof ctx.effect === 'function') {
      ctx.effect(() => {
        const dispose = commands.register(definition)
        return () => dispose()
      })
    } else {
      commands.register(definition)
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    warn(`command registration failed: ${message}`)
  }
}

export function apply(ctx, rawConfig) {
  const config = normalizeConfig(rawConfig)
  let mode = config.mode

  registerCommand(ctx, config, () => mode, value => {
    mode = value
  })

  ctx.on('tools/pre-execute', async (exec, next) => {
    if (mode === 'off') return next()
    if (exec === null || typeof exec !== 'object' || typeof exec.name !== 'string') return next()
    if (exec.signal !== undefined && exec.signal.aborted) return { kind: 'cancel' }

    const cwd = await sessionCwd(ctx, exec)

    let decision
    try {
      decision = classifyToolCall({ name: exec.name, args: exec.arguments, cwd, config })
    } catch (error) {
      // Fail closed: an unclassifiable call still needs a human decision.
      const message = error instanceof Error ? error.message : String(error)
      warn(`classification failed for ${exec.name}: ${message}`)
      decision = {
        kind: 'unclassified',
        risk: 'normal',
        reason: `write-approval-guard could not classify ${exec.name}: ${message}`,
        displayReason: {
          en: `The write-approval guard could not classify ${exec.name}. Approve only if you trust this call.`,
          zh: `写操作审批守卫无法判定 ${exec.name}，请确认后再批准。`,
        },
      }
    }

    if (decision === null) return next()

    // `gateWrites: "risky"` trades per-write approval for attention: ordinary
    // writes pass, only system/destructive/sensitive decisions stop here.
    if (config.gateWrites === 'risky' && (decision.kind === 'write' || decision.kind === 'shell-write')) {
      return next()
    }

    if (decision.risk === 'high' && config.highRiskConfirmations === 'double') {
      const first = await confirmHighRisk(ctx, exec, decision, config)
      if (first !== null) return first
      decision = withSecondStep(decision)
    }

    // `onReject: "turn"` needs the outcome, so this plugin asks the ordinary
    // approval itself instead of delegating it to the runtime.
    if (config.onReject === 'turn') {
      const outcome = await requestDecision(ctx, exec, decision)
      if (outcome.allowed === true) return next()
      if (outcome.cancelled === true) return { kind: 'cancel' }
      if (outcome.rejected === true) return rejectionDecision(exec, decision, 'approval-rejected', config)
      return denyDecision(decision, outcome.tag)
    }

    if (exec.signal !== undefined && exec.signal.aborted) return { kind: 'cancel' }

    return {
      kind: 'ask',
      reason: decision.reason,
      displayReason: decision.displayReason,
    }
  })
}

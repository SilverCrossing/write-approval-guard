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
 * The policy is resolved per call in three layers: a per-session override set
 * by the human-only command `/write-guard …`, an absolute-root workspace
 * binding (`workspaces:`), and the configured default. Slash commands cannot be
 * issued by the model, so the runtime switch cannot be used to widen its own
 * access, and an override is never inherited by a subagent.
 */
import {
  classifyToolCall,
  DEFAULT_PROTECTED_PATTERNS,
  DEFAULT_SENSITIVE_PATTERNS,
} from './classify.js'
import { createLogger } from './log.js'
import { createSessionOverrides, matchWorkspace, normalizeWorkspaces, sessionKey } from './scope.js'

export const name = 'write-approval-guard'

/** `tools` is the only hard dependency; `approval` and `commands` are optional. */
export const inject = ['tools']

const MODES = new Set(['enforce', 'off'])
const GATE_MODES = new Set(['all', 'risky', 'workspace'])

/** Normalize a write-gate policy, falling back to `fallback` when unset. */
function normalizeGate(value, fallback) {
  return GATE_MODES.has(value) ? value : fallback
}
const DEFAULT_MODE = 'enforce'
const ON_REJECT = new Set(['call', 'turn'])

function warn(message) {
  console.warn(`[write-approval-guard] ${message}`)
}

/** Promise-based delay used by the confirmation gap. */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
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
  const gateWrites = normalizeGate(config.gateWrites, 'all')
  if (config.gateWrites !== undefined && !GATE_MODES.has(config.gateWrites)) {
    warn('config.gateWrites must be "all", "risky" or "workspace"; keeping "all"')
  }
  // Subagents have no approval channel, so their policy can differ from the
  // main session's. `null` means "inherit whatever this call resolves to",
  // which is not the same as a frozen copy of `gateWrites`: a workspace binding
  // must still reach a subagent that was given no policy of its own.
  const subagentGateWrites = GATE_MODES.has(config.subagentGateWrites) ? config.subagentGateWrites : null
  if (config.subagentGateWrites !== undefined && !GATE_MODES.has(config.subagentGateWrites)) {
    warn('config.subagentGateWrites must be "all", "risky" or "workspace"; inheriting gateWrites')
  }
  // Absolute-root bindings that replace the default for one workspace.
  const workspaces = normalizeWorkspaces(config.workspaces, 'workspaces', GATE_MODES, warn)
  return {
    mode,
    log: config.log !== false,
    logDir: typeof config.logDir === 'string' ? config.logDir.trim() : '',
    logRetentionDays: Number.isFinite(config.logRetentionDays) ? config.logRetentionDays : 7,
    confirmGapMs: Number.isFinite(config.confirmGapMs) && config.confirmGapMs >= 0 ? Math.floor(config.confirmGapMs) : 2000,
    onReject,
    unknownTools,
    gateWrites,
    subagentGateWrites,
    workspaces,
    extraConfigPaths: stringList(config.extraConfigPaths, 'extraConfigPaths', []),
    protectedPaths: stringList(config.protectedPaths, 'protectedPaths', DEFAULT_PROTECTED_PATTERNS),
    highRiskConfirmations,
    sensitiveReadConfirmations,
    gateShell: config.gateShell !== false,
    gateDelegation: config.gateDelegation !== false,
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
 * Whether one call comes from a subagent instead of a top-level session.
 *
 * `agents.roots()` lists the agents created without an owning agent context;
 * `subagent` and `workflow` children have one, so they are absent from it. A
 * missing service or a thrown lookup counts as top-level, which means the
 * stricter main-session policy applies.
 */
function isSubagentCall(ctx, exec) {
  if (exec.agent === undefined || exec.agent === null) return false
  const agents = ctx.get('agents')
  if (agents === undefined || typeof agents.roots !== 'function') return false
  try {
    return !agents.roots().some(agent => agent.id === exec.agent.id)
  } catch {
    return false
  }
}

/**
 * Cooperative stop of the current turn: `agent.cancel({ kind: 'user' })` aborts
 * the current activity, clears pending work, and keeps already delivered stream
 * text. It does not kill a process or discard the session.
 *
 * 中文：协作式停止本轮。cancel 必须带 cause（这里是 user，语义等于“用户自己
 * 按了停止”），运行时会把它记进 turn/end；不带 cause 会触发内部断言。
 */
function stopTurn(exec) {
  const agent = exec.agent
  if (agent === undefined || agent === null || typeof agent.cancel !== 'function') {
    warn('onReject is "turn" but the agent has no cancel(); the rejection only stops this call')
    return false
  }
  try {
    // `cancel` takes a required cause: the loop copies it into `turn/end` and
    // asserts on anything outside that closed union, so a bare call turns a
    // user stop into an internal failure instead of a recorded abort.
    // 中文：cancel 必须带 cause，运行时会把它复制进 turn/end，并用断言检查
    // 取值是否在合法集合内；不带 cause 会把“用户停止”变成内部错误。
    agent.cancel({ kind: 'user' })
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
      en: `Step 1 of 2 — open the final confirmation. ${decision.displayReason.en} Nothing runs here: approving only opens the second dialog.`,
      zh: `第 1/2 次确认——开启最终确认。${decision.displayReason.zh}此处不会执行：批准后会停顿，再弹出第 2 次确认。`,
    },
  })
  if (outcome.allowed === true) return null
  if (outcome.cancelled === true) return { kind: 'cancel' }
  if (outcome.rejected === true) return rejectionDecision(exec, decision, 'approval-rejected', config)
  return denyDecision(decision, outcome.tag)
}

/**
 * Re-label a decision as the ordinary (second) confirmation.
 *
 * `kind` and `risk` must survive: the decision log records them, and dropping
 * them here made the second step show up as `unknown`/`normal` in older builds.
 */
function withSecondStep(decision) {
  return {
    kind: decision.kind,
    risk: decision.risk,
    reason: decision.reason,
    displayReason: {
      en: `Step 2 of 2 — final high-risk confirmation. ${decision.displayReason.en} The call runs immediately after approval.`,
      zh: `第 2/2 次确认——高危操作，最终确认。${decision.displayReason.zh}批准后将立即执行。`,
    },
  }
}

function usage() {
  return [
    '用法：/write-guard [status|all|workspace|risky|on|off|reset]',
    '  status    — 显示配置默认、工作区绑定与本会话生效值',
    '  all       — 本会话：每次写入都审批',
    '  workspace — 本会话：工作区内普通写入放行',
    '  risky     — 本会话：只拦高危与敏感操作',
    '  on        — 本会话：重新启用审批（不改门禁档位）',
    '  off       — 本会话：临时关闭审批',
    '  reset     — 清除本会话覆盖，回到配置/工作区绑定',
    '',
    '以上覆盖只作用于当前会话，重启后失效；子代理不受影响。',
  ].join('\n')
}

const SOURCE_LABEL = { config: '配置默认', workspace: '工作区绑定', session: '本会话覆盖' }

/**
 * Effective policy for one call: session override > workspace binding > config.
 *
 * A subagent resolves through its own knob first (`subagentGateWrites`) and then
 * through the same binding/default chain, but never through a session override
 * or a session-level `off`: its policy must not loosen because one human made
 * one conversation more relaxed.
 */
function resolvePolicy({ config, overrides, sessionId, cwd, scope }) {
  const override = overrides.get(sessionId)
  const binding = matchWorkspace(cwd, config.workspaces)
  const bound = binding === null ? undefined : binding.mode
  if (scope === 'subagent') {
    return {
      mode: config.mode,
      gateWrites: config.subagentGateWrites ?? bound ?? config.gateWrites,
      source: config.subagentGateWrites !== null ? 'config' : binding === null ? 'config' : 'workspace',
      binding,
      override: undefined,
    }
  }
  return {
    mode: override?.mode ?? config.mode,
    gateWrites: override?.gateWrites ?? bound ?? config.gateWrites,
    source: override === undefined ? (binding === null ? 'config' : 'workspace') : 'session',
    binding,
    override,
  }
}

/** Human label for one write-gate policy. */
function gateLabel(value) {
  return value === 'all' ? '全部写入' : value === 'risky' ? '仅高风险' : '工作区内放行'
}

function statusText({ config, overrides, sessionId, cwd }) {
  const policy = resolvePolicy({ config, overrides, sessionId, cwd, scope: 'main' })
  const high = config.highRiskConfirmations === 'double' ? '两次确认' : '仅一次确认'
  const subagent = config.subagentGateWrites === null ? '继承解析结果' : gateLabel(config.subagentGateWrites)
  const binding = policy.binding === null
    ? (config.workspaces.length === 0 ? '未配置' : '未命中（当前会话不在任何绑定根下）')
    : `${policy.binding.root} → ${gateLabel(policy.binding.mode)}`
  return [
    `写操作审批：${policy.mode === 'enforce' ? '启用' : '已关闭'}（本会话 · 门禁 ${gateLabel(policy.gateWrites)} · 来源：${SOURCE_LABEL[policy.source]}）`,
    `配置默认：${config.mode === 'enforce' ? '启用' : '已关闭'} · 门禁 ${gateLabel(config.gateWrites)}（子代理：${subagent}）`,
    `工作区绑定：${binding}`,
    `拒绝行为：${config.onReject === 'turn' ? '拒绝并停止本轮' : '仅拒绝本次调用'}`,
    `未登记工具：${config.unknownTools === 'ask' ? '审批' : '放行'}`,
    `高危操作：${high}`,
    `敏感读取：${config.sensitiveReadConfirmations === 'double' ? '两次确认' : '一次确认'}`,
    `命令行：${config.gateShell ? `检查（${config.shellMode}）` : '不检查'}`,
    `敏感规则：${config.sensitivePaths.length} 条；额外系统路径：${config.extraSystemRoots.length} 条；豁免路径：${config.exemptPaths.length} 条`,
  ].join('\n')
}

/** The session directory an invocation addresses, or null. */
async function sessionDirFor(ctx, agent) {
  const workingDirectory = ctx.get('workingDirectory')
  if (workingDirectory === undefined || typeof workingDirectory.ensure !== 'function') return null
  if (agent === undefined || agent === null) return null
  try {
    return await workingDirectory.ensure(agent)
  } catch {
    return null
  }
}

function registerCommand(ctx, config, overrides, logger) {
  const commands = ctx.get('commands')
  if (commands === undefined || typeof commands.register !== 'function') {
    warn('commands service unavailable; /write-guard is not registered')
    return
  }
  try {
    const definition = {
      name: 'write-guard',
      description: '切换本会话的写操作审批：all / workspace / risky / on / off / reset / status。',
      input: { hint: 'status | all | workspace | risky | on | off | reset' },
      handler: async (invocation) => {
        const argument = invocation.rawInput.trim().toLowerCase()
        const sessionId = sessionKey(invocation.agent)
        const cwd = await sessionDirFor(ctx, invocation.agent)
        const report = () => statusText({ config, overrides, sessionId, cwd })
        const changed = (text) => {
          const current = overrides.get(sessionId)
          logger.write({
            event: 'mode',
            mode: current?.mode ?? config.mode,
            gateWrites: current?.gateWrites ?? config.gateWrites,
            session: sessionId === '' ? undefined : sessionId,
          })
          return { kind: 'success', text: `${text}\n${report()}` }
        }
        if (argument === '' || argument === 'status') {
          return { kind: 'success', text: report() }
        }
        if (GATE_MODES.has(argument)) {
          // Choosing a gate also enables the guard in this session: "workspace"
          // after "off" is meant to turn something back on.
          overrides.patch(sessionId, { gateWrites: argument, mode: 'enforce' })
          return changed(`本会话写入门禁已切换为「${gateLabel(argument)}」。`)
        }
        if (argument === 'on' || argument === 'enforce') {
          overrides.patch(sessionId, { mode: 'enforce' })
          return changed('本会话已启用写操作审批。')
        }
        if (argument === 'off') {
          overrides.patch(sessionId, { mode: 'off' })
          return changed('本会话已临时关闭写操作审批。')
        }
        if (argument === 'reset') {
          overrides.delete(sessionId)
          return changed('已清除本会话的覆盖，回到配置默认或工作区绑定。')
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
  const logger = createLogger('write-approval-guard', config)
  const pending = new Map()
  const MAX_PENDING = 256

  /**
   * Remember which call this plugin asked about, so the approval outcome can
   * be attached to it later. Bounded: a call whose approval never arrives (or
   * whose process was restarted) is dropped instead of leaking memory.
   */
  function rememberAsk(exec, decision) {
    if (exec.callId === undefined) return
    if (pending.size >= MAX_PENDING) {
      const oldest = pending.keys().next().value
      if (oldest !== undefined) pending.delete(oldest)
    }
    pending.set(exec.callId, { tool: exec.name, kind: decision.kind ?? 'unknown', risk: decision.risk ?? 'normal' })
  }

  // Observation only: let the normal answerers decide, then record the outcome.
  ctx.on('approval/request', async (request, next) => {
    const outcome = await next()
    try {
      const known = request.callId !== undefined ? pending.get(request.callId) : undefined
      if (known !== undefined) {
        pending.delete(request.callId)
        logger.write({ event: 'approval', outcome, tool: known.tool, kind: known.kind, risk: known.risk, agent: request.agent?.id, callId: request.callId })
      }
    } catch {
      // Logging must never change the approval outcome.
    }
    return outcome
  })

  const overrides = createSessionOverrides()

  registerCommand(ctx, config, overrides, logger)

  // A disposed agent must not leave an override behind: a later agent that
  // reuses the id would inherit a mode nobody chose.
  ctx.on('agent/disposed', payload => {
    const agent = payload !== null && typeof payload === 'object' ? payload.agent : undefined
    const key = sessionKey(agent)
    if (key !== '') overrides.delete(key)
  })

  // Pipeline for one call:
  //   classify → (risky mode: pass ordinary writes) → high-risk step 1/2
  //   → (turn mode: ask here) or (call mode: hand `ask` to the runtime)
  // Every branch that stops the call writes one decision log line first.
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec === null || typeof exec !== 'object' || typeof exec.name !== 'string') return next()
    if (exec.signal !== undefined && exec.signal.aborted) return { kind: 'cancel' }

    const scope = isSubagentCall(ctx, exec) ? 'subagent' : 'main'
    const sessionId = sessionKey(exec.agent)
    const cwd = await sessionCwd(ctx, exec)
    const policy = resolvePolicy({ config, overrides, sessionId, cwd, scope })
    if (policy.mode === 'off') return next()

    // Every decision line carries the effective gate and where it came from, so
    // "why was this allowed" is answerable from the log alone.
    const meta = {
      gateWrites: policy.gateWrites,
      modeSource: policy.source,
      session: sessionId === '' ? undefined : sessionId,
    }

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

    const gateWrites = policy.gateWrites

    // `gateWrites: "risky"` trades per-write approval for attention: ordinary
    // writes pass, only system/destructive/sensitive decisions stop here.
    if (gateWrites === 'risky' && (decision.kind === 'write' || decision.kind === 'shell-write')) {
      logger.write({ event: 'allow', rule: 'risky', scope, ...meta, tool: exec.name, risk: decision.risk, kind: decision.kind, agent: exec.agent?.id, callId: exec.callId })
      return next()
    }

    // `gateWrites: "workspace"` frees ordinary file edits inside the session
    // directory and keeps everything else gated. It deliberately does not cover
    // `shell-write`: a command can write anywhere, and the file sandbox is not
    // assumed to be intact.
    if (gateWrites === 'workspace' && decision.kind === 'write' && decision.inWorkspace === true) {
      logger.write({ event: 'allow', rule: 'workspace-write', scope, ...meta, tool: exec.name, risk: decision.risk, kind: decision.kind, agent: exec.agent?.id, callId: exec.callId })
      return next()
    }

    if (decision.risk === 'high' && config.highRiskConfirmations === 'double') {
      rememberAsk(exec, decision)
      logger.write({ event: 'ask', rule: 'high-risk-step1', ...meta, tool: exec.name, kind: decision.kind, risk: decision.risk, reason: String(decision.reason ?? '').slice(0, 300), agent: exec.agent?.id, callId: exec.callId })
      const first = await confirmHighRisk(ctx, exec, decision, config)
      if (first !== null) {
        logger.write({ event: first.kind === 'cancel' ? 'cancel' : 'deny', ...meta, tool: exec.name, kind: decision.kind, risk: decision.risk, rule: 'high-risk-step1', reason: String(decision.reason ?? '').slice(0, 300), agent: exec.agent?.id, callId: exec.callId })
        return first
      }
      decision = withSecondStep(decision)
      // A mandatory pause before the second dialog: it turns a reflex double
      // click into a decision, without changing either dialog's wording.
      if (config.confirmGapMs > 0) {
        await sleep(config.confirmGapMs)
        if (exec.signal !== undefined && exec.signal.aborted) return { kind: 'cancel' }
      }
    }

    // `onReject: "turn"` needs the outcome, so this plugin asks the ordinary
    // approval itself instead of delegating it to the runtime.
    if (config.onReject === 'turn') {
      rememberAsk(exec, decision)
      const outcome = await requestDecision(ctx, exec, decision)
      if (outcome.allowed === true) {
        logger.write({ event: 'allow', ...meta, tool: exec.name, kind: decision.kind, risk: decision.risk, onReject: 'turn', agent: exec.agent?.id, callId: exec.callId })
        return next()
      }
      if (outcome.cancelled === true) {
        logger.write({ event: 'cancel', ...meta, tool: exec.name, kind: decision.kind, risk: decision.risk, agent: exec.agent?.id, callId: exec.callId })
        return { kind: 'cancel' }
      }
      if (outcome.rejected === true) {
        logger.write({ event: 'deny', ...meta, tool: exec.name, kind: decision.kind, risk: decision.risk, rule: 'rejected', reason: String(decision.reason ?? '').slice(0, 300), agent: exec.agent?.id, callId: exec.callId })
        return rejectionDecision(exec, decision, 'approval-rejected', config)
      }
      logger.write({ event: 'deny', ...meta, tool: exec.name, kind: decision.kind, risk: decision.risk, rule: outcome.tag, agent: exec.agent?.id, callId: exec.callId })
      return denyDecision(decision, outcome.tag)
    }

    if (exec.signal !== undefined && exec.signal.aborted) return { kind: 'cancel' }

    rememberAsk(exec, decision)
    logger.write({ event: 'ask', ...meta, tool: exec.name, kind: decision.kind, risk: decision.risk, reason: String(decision.reason ?? '').slice(0, 300), agent: exec.agent?.id, callId: exec.callId })
    return {
      kind: 'ask',
      reason: decision.reason,
      displayReason: decision.displayReason,
    }
  })
}

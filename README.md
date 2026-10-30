# 写操作审批守卫（write-approval-guard）

[English](README_EN.md) | 中文

把「写文件」和「读敏感配置」变成必须经过人的动作：工作区内的写也要审批，破坏性或系统级操作要**两次**确认，读取 `.env`、`.config`、密钥之类的文件同样要审批。

和 `outside-access-guard` 是正交的两层：那一层管「工作区之外」，这一层管「写」和「敏感读」。两者共存时的具体行为见「与 outside-access-guard 的联动」。

## 设计权衡：子代理没有审批通道

> 这不是 bug，是设计上的取舍。

子代理（`subagent`、`workflow` 里的 `agent()`）是独立会话，**没有绑定审批答复者**。所以它发起的写操作、越界访问、高危操作一律 **fail closed**：

- 不会弹窗到任何地方；
- 不会挂起等待，而是立即被拒绝；
- 模型收到的文案是 `the user rejected tool "…"`，看起来像人拒绝，实际是“没有可用的审批通道”；
- 这类调用在日志里只有 `ask`、没有 `approval` 结果行——旁听瀑布根本没被调到。

为什么这么设计：审批的前提是“有人看见”。给子代理一条无人确认就能放行的通道，等于在这条链上开了个洞；而“自动批准”比“自动拒绝”危险得多。宁可让子代理只读，也不做这个让步。

**影响**：委派写任务必然失败；子代理适合读文件、跑只读命令、做分析。真正要落地的修改，只能由有 UI 会话的 agent 完成——它的每一步都要你点。需要子代理产出改动时，让父会话代跑。

## 三类判定

| 判定 | 触发条件 | 确认次数 |
| --- | --- | --- |
| 写操作 | `write` / `edit` 任意路径；命令行可能写盘 | 1 次 |
| 高危 | 磁盘/格式化、递归或通配删除、系统配置或系统目录、权限/所有权 | **2 次** |
| 敏感读取 | 读取 `.env`、`.config`、密钥、凭据、浏览器会话等 | 1 次 |

高危的两次确认是：

1. **第 1/2 次**：单独的 `approval.request`，只负责"开启最终确认"，本身不执行任何操作；
2. **停顿**：两次之间强制等待 `confirmGapMs`（默认 2000 毫秒），避免连点掠过；
3. **第 2/2 次**：这次调用的常规审批（`kind: 'ask'`）——**高危警告文案放在这一层**，因为带停顿的这次才会被真正注意到。

两次都批准才执行；任一步拒绝都不会执行，取消则直接取消。批准结果是 `allowed-once`，不会出现「本次会话以后都允许」。

## 降级模式：`gateWrites: risky`

逐个审批普通写入，在长任务里会退化成“确认噪声”——前几次还看，后面只是点鼠标，真正危险的那次反而被淹没。`gateWrites: risky` 把门禁收窄到“人会认真看的那几类”：

| 判定 | `all`（默认） | `risky` |
| --- | --- | --- |
| 普通写入（`write` / `safe_write` / `edit` / `safe_edit` / `multi_edit`） | 审批 | **放行** |
| 普通命令行写（`Set-Content x.txt`、未知命令） | 审批 | **放行** |
| 敏感文件读写（`.env`、`.config`、密钥） | 审批 | 审批 |
| 系统路径写入 / 磁盘格式化 / 递归删除 / 权限修改 | 两次确认 | **两次确认** |
| 未登记工具（`unknownTools: ask` 时） | 审批 | 审批 |

也就是说：**只有“罕见且不可逆”的操作还会打断你**，普通重构不会。

代价很明确：普通写不再有人把关，出问题只能靠快照回滚（配合 `dsh-safety-toolkit` 时每个文件都有备份）。这是拿“每次确认”换“确认的有效性”。

## 工作区模式：`gateWrites: workspace`

介于 `all` 和 `risky` 之间的第三档：**工作区内的普通写放行，其它一切照旧审批**。

| 判定 | `workspace` |
| --- | --- |
| 工作区内的 `write` / `safe_write` / `edit` / `safe_edit` / `multi_edit` | **放行** |
| 同上，但目标在工作区外 | 审批 |
| 同上，但命中 `protectedPaths` | 审批 |
| 命令行写（`shell-write`，包含未知命令） | **审批** |
| 系统路径 / 配置行为文件 / 递归删除 / 敏感读写 | 审批（高危仍两次） |

两个刻意的取舍：

1. **不覆盖 `shell-write`**。命令能写到任何地方，而且沙箱不总是可靠，所以命令执行仍然逐次审批。
2. **不放行保护路径**。`protectedPaths` 默认只拦“会在以后自动执行的东西”：`.git/**`、`.dsh/**`、`node_modules/.bin/**`、`.github/workflows/**`。要保护自己的插件仓库，把它加进这个列表。

判定**不依赖文件沙箱**：目标会先 `resolve` 再 `realpath`，然后判断是否在会话目录内；解析不出来按“工作区外”处理。多文件调用（`multi_edit`）只要有一个目标在外面或受保护，整个调用就要审批。

典型用途是**给子代理一点工作能力**：子代理没有审批通道，`all` 模式下连改一行都会被拒绝；`workspace` 模式下它可以编辑工作区文件，但仍然执行不了命令、碰不了配置与系统路径。

### 只放开子代理

主会话逐次审批、子代理能改文件，这是两个独立的旋钮：

```yaml
gateWrites: all
subagentGateWrites: workspace
```

判定用 `agents.roots()`（顶层 agent 列表）：不在列表里的视为子代理。服务不可用或查询抛错时按**主会话**处理，也就是采用更严的那一档。日志里的 `allow` 行会带 `scope: "main" | "subagent"`，事后能分辨是谁被放行的。

注意 `subagentGateWrites: risky` 是**危险组合**：它会连 shell 命令一起放行，而子代理没有审批通道来兑底。

## 委派审批：`gateDelegation`

`subagent`、`subagent_fork`、`workflow`、`spawn_teammate` 不写文件，但一次调用可以开出一整棵树——子代理还能再派子代理，几十个一起烧 token。

默认开启（`gateDelegation: true`）：每次委派一次审批，文案里带目标描述；`workflow` 会额外报告脚本里 `agent()` 的调用次数（脚本会扇出多少个）。

一个副作用是**递归被截断**：子代理没有审批通道，它自己再想派子代理时会被 fail-closed。所以除非你在主会话逐层批准，委派深度天然不超过一层。

这条与 `gateWrites` 无关：`risky` 和 `workspace` 档都不会放行委派。

## 高危清单

默认开启以下六类（`highRiskConfirmations: single` 可整体退化成单次）：

| 类别 | 例子 |
| --- | --- |
| 磁盘/格式化 | `format C:`、`diskpart`、`Clear-Disk`、`Initialize-Disk`、`mkfs`、`dd if=`、`cipher /w` |
| 递归/通配删除 | `Remove-Item -Recurse`、`Remove-Item *`、`rm -rf`、`rd /s`、`del /f /s`、`del *.*` |
| 系统配置/系统目录 | `reg add|delete`、`Set-ItemProperty HKLM:`、`sc config|delete`、`Set-Service`、`bcdedit`、`netsh`、`shutdown`、`schtasks /create`、`setx`、`Set-ExecutionPolicy`、写 `C:\Windows`、`C:\Program Files`、`/etc`、`/usr` |
| 权限/所有权 | `icacls /reset|grant`、`cacls`、`takeown /f`、`chmod -R`、`chown -R`、`chmod 777` |
| 下载即执行 | `iwr … \| iex`、`curl … \| bash`、`iex (…DownloadString…)`——你只能看到 URL，看不到载荷 |
| 自主性工具 | `schedule_create`、`schedule_update`、`create_goal`、`update_goal`（`edit` / `resume`）——会在你离开后继续工作 |

破坏性 Git（`reset --hard`、`clean -xdf`）和包管理器写入**不算**高危，只走单次审批；这是按使用者的选择定的，避免日常疲劳。

## 配置与行为文件

写入下面这些文件会获得**超出单次编辑的持续影响力**——shell 启动脚本下次登录就执行、git hook 下次提交就运行、编辑器任务文件在打开目录时执行、`.dsh-prompts/**` 会进入系统提示词。所以它们单独归为高危（两次确认），既不是普通写也不是“敏感写”：

| 类别 | 路径 |
| --- | --- |
| shell 启动脚本 | `.bashrc`、`.bash_profile`、`.profile`、`.zshrc`、`.zprofile`、PowerShell `profile.ps1` |
| git 钩子与配置 | `.git/hooks/**`、`.git/config`、`.gitmodules` |
| 编辑器自动执行 | `.vscode/tasks.json`、`.vscode/launch.json`、`.vscode/settings.json`、`.vscode/mcp.json` |
| 影响 AI 行为的文件 | `AGENTS.md`、`CLAUDE.md`、`.cursorrules`、`.dsh-prompts/**` |
| 环境与包管理配置 | `.env*`、`.npmrc`、`.yarnrc`、`pip.conf`、`cordis.patch.yml` |
| 应用配置目录与文件 | `.config`、`.config/**`、`*.config` |

命令行写这些文件（`Set-Content $PROFILE`、`echo x > .bashrc`）同样升为高危。`extraConfigPaths` 可以追加自己的路径。

注意：`.env` 的写入因此从“单次审批”变成“两次确认”——环境变量属于持久影响力，值得多一下。

## 敏感读取

默认匹配（可用 `sensitivePaths` 覆盖；传 `[]` 关闭）：

```
**/.env  **/.env.*  **/*.env  **/.envrc
**/.npmrc  **/.pypirc  **/.netrc  **/.git-credentials
**/*.pem  **/*.key  **/*.pfx  **/*.p12  **/*.keystore  **/*.jks  **/*.ppk
**/id_rsa*  **/id_ed25519*  **/id_ecdsa*
**/.config  **/.config/**
**/.ssh/**  **/.aws/**  **/.azure/**  **/.gnupg/**  **/.kube/**
**/.docker/config.json  **/.dsh/.credentials.yaml
**/credentials*  **/secrets.*  **/*.secret  **/*.password  **/passwords.*
**/Login Data  **/Cookies  **/Local State  **/logins.json  **/key4.db
```

匹配同时使用词法路径和真实路径（符号链接解析后），Windows 下不区分大小写。`.config` 按使用者的选择包含目录内全部内容，所以读 `~/.config/...` 也会弹窗。

## 覆盖范围

| 工具 | 判定字段 | 说明 |
| --- | --- | --- |
| `write` / `edit` | `file_path` | 任意路径都审批；系统路径升为高危 |
| `read` / `read_image` | `file_path` | 仅敏感文件审批 |
| `grep` | `path`、`include` | 目录敏感或 `include` 命中敏感名（如 `*.env`）都审批 |
| `glob` | `path` | 仅当目录本身敏感（列 `.ssh` 也算） |
| `pwsh` / `bash` / `shell` | `command`、`workdir` | 高危模式 → 写 → 敏感读 → 只读放行；未知命令按写处理 |

不在表里的工具（例如 MCP 提供的 `write_file`）**不会被拦截**——无法可靠判断它们的参数语义。需要的话用 `ignoreTools` 做反向名单（放行某些工具），目前没有「未知工具一律拦」的开关。

## 工具覆盖与兼容性

判定是**按工具名**做的。没有任何可靠启发式能回答"这个没见过的工具会不会写文件"，所以未列出的工具一律放行——这是本插件最大的结构性限制。

### 已覆盖

| 工具 | 来源 | 判定字段 |
| --- | --- | --- |
| `write` / `edit` | 原生 | `file_path` |
| `read` / `read_image` / `grep` / `glob` | 原生 | 敏感读判定 |
| `pwsh` / `bash` / `shell` | 原生 | 命令文本启发式 |
| `safe_write` / `safe_edit` / `safe_rollback` | [dsh-safety-toolkit](https://github.com/SilverCrossing/dsh-safety-toolkit) | `filepath`；回滚的文案会说明「会覆盖当前内容」与目标快照 |
| `multi_edit` | 同上 | `edits[].file`（逐项判定，取最高风险） |
| `test_runner` | 同上 | 无路径，按"执行项目代码"单次审批 |
| `syntax_check` / `safe_backups` | 同上 | 只读或只动备份元数据，不拦 |

`dsh-safety-toolkit` 的 governance 会把 `write`/`edit` 从工具表里移除，所以那套 `safe_*` 名字必须单列——否则护栏会被"安全工具"整体绕过。

另外，`safe_*` 系列由工具自身强制**工作区包含**：越界路径会在执行前被它拒绝（`路径越界`）。所以工作区外的写入仍然只能走原生 `write` + 沙箱一次性升级，审批通过也不代表能越界。

### 不会覆盖

- 其他插件替换出来的写工具（例如 `foo_write`、`atomic_patch`）；
- MCP server 提供的 `write_file` / `edit_file` / `apply_patch`；
- 任何以后新增的写类工具。

**也就是说：装了别的"原生工具替换"或"额外注册写工具"的插件时，本护栏对它们不生效。** 那些调用不会弹审批，也不会触发系统路径或敏感文件判定。安装这类插件前，请先确认它是否自带审批机制。

自查方法：看那个插件暴露的工具名。不在上表里的，就是未覆盖的。

想加一个：在 issue 里给出工具名和它的路径参数名（例如 `name: "foo_write", path: "target"`），加一行映射即可；`multi_edit` 那种数组参数需要说明路径所在的字段。

`ignoreTools` 只能**收窄**（放行某些已覆盖的工具），不能用来扩大覆盖范围。

### 兜底：`unknownTools: ask`

默认 `allow`：未登记的工具直接放行。设为 `ask` 后，**任何不在上表里的工具都会弹一次审批**——这才是真正的 fail-closed。

代价是噪音：`web_search`、`todo_write`、`schedule_create` 这类只读或无关工具也会被拦。实际用法是把确定无害的工具加进 `ignoreTools`：

```yaml
- id: write-approval-guard
  config:
    unknownTools: ask
    ignoreTools: [web_search, web_fetch, todo_write, schedule_list, job_list, present, skill]
```

这是黑名单式补丁：以后装了新的只读插件，它会开始弹窗，需要手动加进 `ignoreTools`。

### 自行扩展

本项目是 MIT 协议，可以 fork 后直接改 `classify.js` 里的 `WRITE_TOOL_PATHS`——一行一个 `工具名: args => [路径字段]` 映射——或发布自己的兼容版。也欢迎提 issue 把常用工具合并进来。

## 配置

```yaml
- id: write-approval-guard
  config:
    mode: enforce                  # enforce | off
    log: true                      # 记录拦截决定
    logDir: ''                     # 默认 <DSH_HOME>/logs/write-approval-guard
    logRetentionDays: 7            # 超过 N 天自动删除（0 = 永不删除）
    confirmGapMs: 2000             # 二次确认之间的强制停顿（毫秒，0 = 关闭）
    onReject: call                 # call | turn
    unknownTools: allow            # allow | ask
    gateWrites: all                # all | risky | workspace
    subagentGateWrites: ''         # all | risky | workspace；留空 = 继承 gateWrites
    protectedPaths: []             # 省略=默认规则；[]=关闭；命中仍审批
    extraConfigPaths: []           # 追加“配置/行为文件”路径
    highRiskConfirmations: double  # double | single
    sensitiveReadConfirmations: single  # single | double
    gateShell: true
    gateDelegation: true           # 委派子代理是否也要审批
    shellMode: conservative        # conservative | lenient | off
    sensitivePaths: []             # 省略=默认规则；[]=关闭敏感识别
    extraSystemRoots: []           # 追加系统路径
    exemptPaths: []                # 这些目录下的普通写不拦（系统路径仍拦）
    ignoreTools: []                # 这些工具名下不做任何检查
```

`onReject` 决定"拒绝"的粒度：

| 值 | 含义 |
| --- | --- |
| `call`（默认） | 只拒绝这一次调用。同一批里的后续调用**继续**执行（各自还要审批）。 |
| `turn` | 拒绝后同时**协作式停止本轮**（`agent.cancel()`），模型停下等你指示。 |

`turn` 模式下插件会自己接管普通审批（而不是返回 `ask` 交给运行时），否则拿不到拒绝结果——所以这是唯一会改变审批内部路径的配置，外观不变。

停止是协作式的：中止当前活动、清空待处理、保留已经输出的流式文本；**不杀进程、不丢会话**，你发下一条消息就能继续。代价是它会连带停掉同一轮里你可能还想要的操作。

非法值不会静默生效：加载时会打印带期望值的 `console.warn`，再回落到默认值。

## 斜杠命令

```text
/write-guard status   # 当前模式与规则数量
/write-guard on       # 启用
/write-guard off      # 临时关闭（只存在内存里，重启回到配置值）
```

命令只能由人发出，模型无法调用，因此不能用它给自己扩权。

## 与 outside-access-guard 的联动

两个插件都挂在 `tools/pre-execute`，而瀑布只保留第一个非 `allow` 的决策，所以同一个调用**只会弹一次**——不是重复拦截，是先响应者定调。

当前 profile 的 bundle 顺序是 `outside-access-guard` → `prompt-persona-manager` → `write-approval-guard`，实测结果：

| 场景 | 谁响应 | 弹几次 | 文案 |
| --- | --- | --- | --- |
| 工作区内普通读 | outside 放行 → 本插件判不敏感 | 0 | — |
| 工作区内 `.env` | outside 放行 → 本插件 | 1 | 「读取敏感文件」 |
| 工作区外普通文件 | outside | 1 | 「访问工作区外」 |
| 工作区外 `.env` / `.config` | **outside** | 1 | 「访问工作区外」（不体现“敏感”） |
| 工作区外 `.ssh/id_rsa` | outside | 2 | outside 自己的敏感升级 |

**不要为了让工作区外的 `.env` 显示「敏感」而调换顺序。** 调换后 `.env` 的文案确实更好，但工作区外的私钥会从两次确认降成一次（本插件只做单次敏感读），是拿强度换措辞。当前顺序下，工作区外的高风险判定由 outside 层负责，工作区内和写操作由本插件负责，两者的默认强度一致（单次）。

**配置陷阱**：本插件的 `sensitiveReadConfirmations: double` 只作用于工作区内（以及 outside 层放行的路径）。工作区外已被 outside 层拦下的文件不会走到这里，所以不会跟着变严，也不会报错。要让外面也变严，得改 outside 的敏感清单——注意它的 `sensitivePaths` 是**覆盖**不是追加，写了就替换默认那一长串。

实测记录（2026-10-23，Windows，`workspace-write`）：工作区外的 `.env`、`.config` 均只弹一次，文案为「访问工作区外」；工作区内的 `.env` 弹「读取敏感文件」。

## 日志

每次判定写一行 JSONL 到 `$DSH_HOME/logs/write-approval-guard/YYYY-MM-DD.log`，按本地日期分文件，默认保留 7 天（进程启动时清理一次，之后每 6 小时一次）：

```json
{"ts":"2026-10-24T20:38:35.123+08:00","event":"ask","tool":"pwsh","kind":"destructive","risk":"high","gateWrites":"all","agent":"...","callId":"...","reason":"..."}
```

- `event`：`ask` / `deny` / `cancel` / `allow` / `mode` / `approval`（审批结果：allowed-once / rejected / cancelled / unavailable）；
- 只记录**被判定过**的调用（普通读取不会产生日志）；
- 写日志失败只告警，不影响拦截；
- `log: false` 关闭，`logDir` 换目录，`logRetentionDays` 改保留天数。

## 已知限制

1. **shell 是启发式检查，不是系统级隔离。** 只读白名单、写动词、重定向、高危正则都基于文本；`powershell -EncodedCommand`、`[IO.File]::WriteAllText(...)`、字符串拼接、脚本内部写盘都能绕过。
2. **两步绕过仍然存在**：先在工作区内 `write` 一个脚本（这一次会审批），再用 `pwsh .\x.ps1` 执行（这一次按「未知命令=写」也会审批）——但审批之后脚本内部做什么，本插件看不见。这是工具层围栏的固有上限。
3. **工作区外的写仍会被沙箱拒绝。** 本插件的批准不会放宽 `workspace-write`；那种情况会「确认一次后依然失败」。要真正写出去，必须由调用方显式请求沙箱升级并再获批一次。
4. **每次调用都要点。** 只有 `allowed-once`，没有「允许这一类」的选项；批量改文件会很吵。
5. **`.env.example` 也会被拦**——敏感匹配只看文件名，不做内容或模板判断。
6. **未导出 `Config` schema**（保持零依赖，安装期不拉包），所以插件页没有配置表单，`Config.listConfigs` 显示 `status: "absent"`；配置只写在 patch 里。
7. **与 `outside-access-guard` 共存时只有一个弹窗生效**，工作区外的判定归它，详见上一节。
8. **只覆盖按名字登记的工具。** 其他插件替换或新增的写工具（包括 MCP 的 `write_file`）不会被拦截，见「工具覆盖与兼容性」。
9. **插件源码若留在会话工作区**，模型可以改它。公开分发时用 `git+https://…#<commit>` 或 npm 版本安装，安装副本落在 profile 的 `node_modules`（会话工作区之外），这条才闭合。

## 验证

```powershell
node test/classify.test.mjs   # 28 项：判定规则
node test/apply.test.mjs      # 14 项：装配、两次确认、模式开关
node test/onreject.test.mjs   # 8 项：拒绝行为与停止本轮
node test/summary.test.mjs    # 1 项：确认摘要已移除
node test/safety-toolkit.test.mjs  # 12 项：safe_* 工具覆盖
node test/unknown-tools.test.mjs   # 7 项：未登记工具的兜底
```

安装后建议按这个顺序手工确认（需要人点）：

- `write` 一个工作区内新文件 → 弹 1 次；
- `read .env` → 弹 1 次；
- `pwsh -Command "Remove-Item -Recurse .\build"` → 先弹「第 1/2 次」，批准后再弹「第 2/2 次」；
- `/write-guard off` 后重试 → 不再弹；
- `format C:` 之类**不要真的执行**，用 `--dry-run` 或直接看判定即可。

## 安装 / 卸载

```powershell
dsh plugin --profile desktop add /absolute/path/to/write-approval-guard
dsh plugin --profile desktop remove write-approval-guard
```

纯 Host、零依赖、无网络请求、无 install 脚本。给他人使用时建议用 Git 快照（`git+https://…#<40 位 commit>`）或 npm 版本安装，而不是 `link:`：这样运行副本在 profile 的 `node_modules` 里，不会被会话里的模型改写。

## 许可证

MIT，见 [LICENSE](LICENSE)。

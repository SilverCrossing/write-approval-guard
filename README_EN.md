# write-approval-guard

Turn "write a file" and "read a secret" into actions a human must approve: writes inside the workspace are gated too, destructive or system-level operations need **two** confirmations, and reading `.env`, `.config`, keys and similar files needs approval as well.

It is orthogonal to `outside-access-guard`: that layer owns "outside the workspace", this one owns "writes" and "sensitive reads". Their interaction is described in [Interaction with outside-access-guard](#interaction-with-outside-access-guard).

## Three kinds of decisions

| Decision | Trigger | Confirmations |
| --- | --- | --- |
| Write | `write` / `edit` on any path; a shell command that may write | 1 |
| High risk | Disk/format, recursive or wildcard delete, system configuration or system directories, permissions/ownership | **2** |
| Sensitive read | Reading `.env`, `.config`, keys, credentials, browser sessions | 1 |

The two confirmations for a high-risk call are:

1. **Step 1/2** — a dedicated `approval.request` that names the risk and the matched rule;
2. **Step 2/2** — the ordinary approval for this call (`kind: 'ask'`).

Both must be approved; rejecting either step means nothing runs, and cancelling cancels the call. The only grant is `allowed-once` — there is no "allow for the rest of this session".

## Downgrade mode: `gateWrites: risky`

Approving every ordinary write degrades into confirmation noise on a long task: the first few get read, the rest are clicks, and the one dangerous call is drowned out. `gateWrites: risky` narrows the gate to the cases people actually read:

| Decision | `all` (default) | `risky` |
| --- | --- | --- |
| Ordinary write (`write` / `safe_write` / `edit` / `safe_edit` / `multi_edit`) | approve | **pass** |
| Ordinary shell write (`Set-Content x.txt`, unknown commands) | approve | **pass** |
| Sensitive file read/write (`.env`, `.config`, keys) | approve | approve |
| System path write / disk format / recursive delete / permission change | two confirmations | **two confirmations** |
| Unregistered tool (with `unknownTools: ask`) | approve | approve |

In other words, only **rare and irreversible** operations interrupt you; ordinary refactoring does not.

The trade-off is explicit: ordinary writes are no longer reviewed, so recovery depends on snapshots (with `dsh-safety-toolkit` every file has a backup). This trades "a confirmation every time" for "confirmations that mean something".

## High-risk list

Four categories are on by default (`highRiskConfirmations: single` downgrades all of them to one confirmation):

| Category | Examples |
| --- | --- |
| Disk / format | `format C:`, `diskpart`, `Clear-Disk`, `Initialize-Disk`, `mkfs`, `dd if=`, `cipher /w` |
| Recursive / wildcard delete | `Remove-Item -Recurse`, `Remove-Item *`, `rm -rf`, `rd /s`, `del /f /s`, `del *.*` |
| System config / system directories | `reg add|delete`, `Set-ItemProperty HKLM:`, `sc config|delete`, `Set-Service`, `bcdedit`, `netsh`, `shutdown`, `schtasks /create`, `setx`, `Set-ExecutionPolicy`, writes to `C:\Windows`, `C:\Program Files`, `/etc`, `/usr` |
| Permissions / ownership | `icacls /reset|grant`, `cacls`, `takeown /f`, `chmod -R`, `chown -R`, `chmod 777` |

Destructive Git (`reset --hard`, `clean -xdf`) and package-manager writes are **not** high risk — one approval is enough, to avoid daily fatigue.

## Configuration and behavior files

Writing these files grants **influence beyond a single edit**: a shell startup script runs at the next login, a git hook at the next commit, an editor task file when the folder opens, and `.dsh-prompts/**` reaches the system prompt. They are a separate high-risk category (two confirmations), neither an ordinary write nor a "sensitive write":

| Category | Paths |
| --- | --- |
| Shell startup scripts | `.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.zprofile`, PowerShell `profile.ps1` |
| Git hooks and config | `.git/hooks/**`, `.git/config`, `.gitmodules` |
| Editor auto-run | `.vscode/tasks.json`, `.vscode/launch.json`, `.vscode/settings.json`, `.vscode/mcp.json` |
| Files that steer the AI | `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.dsh-prompts/**` |
| Environment and package-manager config | `.env*`, `.npmrc`, `.yarnrc`, `pip.conf`, `cordis.patch.yml` |
| Application config directories and files | `.config`, `.config/**`, `*.config` |

Shell commands that write them (`Set-Content $PROFILE`, `echo x > .bashrc`) are high risk too. `extraConfigPaths` adds your own paths.

Note: writing `.env` therefore moves from one approval to **two** — environment variables are persistent influence, worth the extra step.

## Sensitive reads

Default patterns (override with `sensitivePaths`; pass `[]` to disable):

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

Matching uses both the lexical path and the real path (after resolving symlinks); on Windows it is case-insensitive. `.config` covers the whole directory by design, so reading `~/.config/...` prompts too.

## Coverage

| Tool | Field | Behavior |
| --- | --- | --- |
| `write` / `edit` | `file_path` | Approval on any path; system paths escalate to high risk |
| `read` / `read_image` | `file_path` | Approval only for sensitive files |
| `grep` | `path`, `include` | Approval when the directory is sensitive or `include` matches a sensitive name (e.g. `*.env`) |
| `glob` | `path` | Only when the directory itself is sensitive (listing `.ssh` counts) |
| `pwsh` / `bash` / `shell` | `command`, `workdir` | High-risk pattern → write → sensitive read → allow read-only; unknown commands count as writes |

Tools not listed (for example an MCP `write_file`) are **not intercepted** — their argument semantics cannot be judged reliably. Use `ignoreTools` as a reverse list (exempt some tools); there is no "block every unknown tool" switch.

## Tool coverage and compatibility

Classification is **by tool name**. No reliable heuristic can answer "will this unseen tool write files?", so unlisted tools pass — this is the plugin's biggest structural limit.

### Covered

| Tool | Source | Field |
| --- | --- | --- |
| `write` / `edit` | native | `file_path` |
| `read` / `read_image` / `grep` / `glob` | native | sensitive-read check |
| `pwsh` / `bash` / `shell` | native | command-text heuristic |
| `safe_write` / `safe_edit` / `safe_rollback` | [dsh-safety-toolkit](https://github.com/SilverCrossing/dsh-safety-toolkit) | `filepath`; the rollback dialog states that it overwrites the current content and names the snapshot |
| `multi_edit` | same | `edits[].file` (judged per entry, highest risk wins) |
| `test_runner` | same | no path; treated as "runs project code", one approval |
| `syntax_check` / `safe_backups` | same | read-only or backup metadata only; not gated |

`dsh-safety-toolkit`'s governance removes `write`/`edit` from the tool table, so the `safe_*` names must be listed separately — otherwise the guard is bypassed wholesale by the "safety" tools.

In addition, the `safe_*` tools enforce **workspace containment** themselves: an out-of-workspace path is rejected before execution. Writing outside the workspace therefore still requires the native `write` plus a one-shot sandbox escalation; an approval does not grant that.

### Not covered

- write tools exposed by other plugins that replace the native ones (`foo_write`, `atomic_patch`);
- MCP `write_file` / `edit_file` / `apply_patch`;
- any write tool added later.

**If you install another plugin that replaces native tools or registers extra write tools, this guard does not apply to them.** Those calls prompt nothing and skip the system-path and sensitive-file checks. Before installing such a plugin, check whether it ships its own approval.

How to check: look at the tool names the plugin exposes. Any name missing from the table above is uncovered.

To add one: open an issue with the tool name and its path argument (`name: "foo_write", path: "target"`); array arguments like `multi_edit` need the field that holds the path.

`ignoreTools` can only **narrow** (exempt covered tools); it cannot widen coverage.

### Fallback: `unknownTools: ask`

Default `allow`. With `ask`, **every tool missing from the table prompts once** — real fail-closed.

The cost is noise: `web_search`, `todo_write`, `schedule_create` prompt too. The practical recipe is to exempt the harmless ones:

```yaml
- id: write-approval-guard
  config:
    unknownTools: ask
    ignoreTools: [web_search, web_fetch, todo_write, schedule_list, job_list, present, skill]
```

This is a blacklist-style patch: a newly installed read-only plugin starts prompting and must be added to `ignoreTools`.

### Extending it yourself

MIT licensed: fork and edit `WRITE_TOOL_PATHS` in `classify.js` — one `toolName: args => [pathField]` mapping per line — or publish your own compatible build. Issues adding common tools are welcome.

## Configuration

```yaml
- id: write-approval-guard
  config:
    mode: enforce                  # enforce | off
    log: true                      # append decision logs
    logDir: ''                     # default <DSH_HOME>/logs/write-approval-guard
    logRetentionDays: 7            # delete logs older than N days (0 = keep forever)
    onReject: call                 # call | turn
    unknownTools: allow            # allow | ask
    gateWrites: all                # all | risky
    extraConfigPaths: []           # extra configuration/behavior paths
    highRiskConfirmations: double  # double | single
    sensitiveReadConfirmations: single  # single | double
    gateShell: true
    shellMode: conservative        # conservative | lenient | off
    sensitivePaths: []             # omit = defaults; [] = disable sensitive detection
    extraSystemRoots: []           # extra system paths
    exemptPaths: []                # ordinary writes here are not gated (system paths still are)
    ignoreTools: []                # tools never inspected
```

`onReject` decides what a rejection means:

| Value | Meaning |
| --- | --- |
| `call` (default) | Reject only this call. Later calls in the same batch **continue** (each still needs its own approval). |
| `turn` | Also **stop the current turn** cooperatively (`agent.cancel()`); the model stops and waits for your instruction. |

In `turn` mode the plugin takes over the ordinary approval instead of returning `ask` to the runtime — otherwise it cannot see the rejection. It is the only setting that changes the plugin's internal approval path; the dialog looks the same.

Stopping is cooperative: it aborts the current activity, clears pending work, and keeps streamed text already delivered; **no process is killed and the session is preserved**, so your next message continues. The cost is that it also stops work later in the same turn that you might have wanted.

Invalid values never apply silently: loading prints a `console.warn` with the expected value and falls back to the default.

## Slash command

```text
/write-guard status   # current mode and rule counts
/write-guard on       # enable
/write-guard off      # temporarily disable (in memory only; a restart restores the configured value)
```

Commands can only be issued by a human; the model cannot call them, so it cannot use them to widen its own access.

## Interaction with outside-access-guard

Both plugins hook `tools/pre-execute`, and the waterfall keeps only the first non-`allow` decision, so one call prompts **once** — not duplicate interception, but the first responder sets the tone.

The current bundle order is `outside-access-guard` → `prompt-persona-manager` → `write-approval-guard`; measured results:

| Scenario | Who answers | Dialogs | Text |
| --- | --- | --- | --- |
| Ordinary read inside the workspace | outside passes → this plugin finds nothing sensitive | 0 | — |
| `.env` inside the workspace | outside passes → this plugin | 1 | "reading a sensitive file" |
| Ordinary file outside the workspace | outside | 1 | "access outside the workspace" |
| `.env` / `.config` outside the workspace | **outside** | 1 | "access outside the workspace" (no "sensitive") |
| `.ssh/id_rsa` outside the workspace | outside | 2 | outside's own sensitive escalation |

**Do not reorder to make an outside `.env` say "sensitive".** The wording improves, but an outside private key drops from two confirmations to one (this plugin only performs a single sensitive read) — strength traded for wording. In the current order, outside risk belongs to outside, while inside paths and writes belong here, and both default to single.

**Configuration trap**: this plugin's `sensitiveReadConfirmations: double` only applies inside the workspace (and to paths the outside layer lets through). A file already stopped by outside never reaches this plugin, so it does not get stricter — and nothing warns about it. To harden the outside case, change outside's sensitive list; note that its `sensitivePaths` **replaces** the defaults rather than appending to them.

Measured (2026-10-23, Windows, `workspace-write`): `.env` and `.config` outside the workspace prompted once with "access outside the workspace"; `.env` inside prompted "reading a sensitive file".

## Logging

Every decision appends one JSONL line to `$DSH_HOME/logs/write-approval-guard/YYYY-MM-DD.log`, split by local date and kept for 7 days (cleaned on process start, then at most every six hours):

```json
{"ts":"2026-10-24T20:38:35.123+08:00","event":"ask","tool":"pwsh","kind":"destructive","risk":"high","gateWrites":"all","agent":"...","reason":"..."}
```

- `event`: `ask` / `deny` / `cancel` / `allow` / `mode`;
- only calls that were classified are logged (ordinary reads produce nothing);
- a failed write only warns and never affects interception;
- `log: false` disables it, `logDir` changes the directory, `logRetentionDays` changes retention.

## Known limitations

1. **Shell inspection is heuristic, not system-level isolation.** The read-only allowlist, write verbs, redirection and high-risk patterns are all text-based; `powershell -EncodedCommand`, `[IO.File]::WriteAllText(...)`, string concatenation and writes performed inside a script all get through.
2. **The two-step bypass remains**: write a script inside the workspace (one approval), then run it with `pwsh .\x.ps1` (also one approval, because unknown commands count as writes) — but the plugin cannot see what the script does after approval. This is the inherent ceiling of a tool-layer fence.
3. **Writes outside the workspace are still rejected by the sandbox.** An approval here does not relax `workspace-write`; those calls fail after being confirmed once. Writing outside for real requires the caller to request a sandbox escalation and have it approved separately.
4. **Every call needs a click.** Only `allowed-once`; there is no "allow this class", so bulk edits are noisy.
5. **`.env.example` is gated too** — sensitive matching looks at file names only, not content or templates.
6. **No `Config` schema is exported** (to stay dependency-free and avoid download-at-install), so the plugin page has no settings form and `Config.listConfigs` reports `status: "absent"`; configuration lives in the patch.
7. **Only one dialog takes effect when coexisting with `outside-access-guard`**; outside paths belong to it. See the section above.
8. **Only tools registered by name are covered.** Write tools added or replaced by other plugins (including MCP's `write_file`) are not intercepted — see "Tool coverage and compatibility".
9. **If the plugin source stays inside the session workspace**, the model can modify it. For public distribution install from `git+https://…#<commit>` or npm: the running copy lands in the profile's `node_modules`, outside the session workspace, which is what closes this gap.

## Verification

```powershell
node test/classify.test.mjs         # 28: classification rules
node test/apply.test.mjs            # 14: wiring, double confirmation, mode switch
node test/onreject.test.mjs         # 8: rejection behavior and stopping the turn
node test/summary.test.mjs          # 1: confirms the change digest was removed
node test/safety-toolkit.test.mjs   # 15: safe_* tool coverage
node test/unknown-tools.test.mjs    # 7: unregistered-tool fallback
node test/gate-writes.test.mjs      # 7: gateWrites modes
node test/config-writes.test.mjs    # 9: configuration/behavior file coverage
```

After installing, confirm by hand in this order (each needs a click):

- `write` a new file inside the workspace → one dialog;
- `read .env` → one dialog;
- `pwsh -Command "Remove-Item -Recurse .\build"` → "step 1/2", then "step 2/2" after approval;
- `/write-guard off` and retry → no dialog;
- do **not** actually run `format C:`; use `--dry-run` or inspect the classification instead.

## Install / uninstall

```powershell
dsh plugin --profile desktop add github:SilverCrossing/write-approval-guard#<commit>
dsh plugin --profile desktop remove write-approval-guard
```

Host-only, zero dependencies, no network requests, no install scripts. For distribution prefer a Git snapshot (`git+https://…#<40-char commit>`) or an npm version over `link:`: the running copy then lives in the profile's `node_modules` and cannot be rewritten by the model inside a session.

## License

MIT, see [LICENSE](LICENSE).

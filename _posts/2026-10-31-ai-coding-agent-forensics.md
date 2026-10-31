---
title: "Did the Agent Do It? Incident Response for AI Coding Agents"
date: 2026-10-31 22:30:00 +0530
categories: [Resources, DFIR]
comments: true
pin: true
description: "Where AI coding agents keep their evidence, the fingerprint they leave in the process tree, how transcripts disappear, where the poison sits, and a free triage kit for PowerShell, bash, KAPE, Velociraptor, Kansa, Intune, Sigma and KQL."
image:
  path: /assets/images/ai-agents/agents-banner-light.png
  alt: Did the agent do it? Endpoint forensics for AI coding agents
tags: [ai-agents, mcp, incident-response, claude-code, cursor, codex, copilot, prompt-injection, kape, velociraptor, triage]
---

> **The EDR shows `bash.exe` running `nltest /domain_trusts` on a developer laptop at 02:14. The developer was asleep. Their AI coding agent was not.**

That call is coming to your IR team, if it hasn't already. October made it concrete:

- **Sophos** showed the Aur0ra ransomware operators driving Cursor's agent and frontier models through AD discovery, Kerberoasting and the hunt for backups.
- **CloudSEK** caught a Gentlemen ransomware affiliate running a reverse shell as an MCP tool inside an AI coding assistant.
- And **s1ngularity** (Aug 2025) already proved that malware will happily drive the agents *you* installed, with approvals switched off.

The question on the bridge call is no longer just *what ran*. It is **who ran it: the human, the malware, or the agent?** This post is the answer key: where the evidence lives, the fingerprint an agent leaves, how it disappears, and a triage kit you can deploy tonight.

> **TL;DR**
> - Agent shell commands **never reach PSReadLine or `.bash_history`**. They live in the agent's transcript, to the millisecond, with the prompt that caused them.
> - On Windows, Claude Code wraps every command in `bash -c "source …shell-snapshots… eval '<cmd>' < /dev/null && pwd -P >| …claude-XXXX-cwd"`. Hunt on it.
> - Transcripts age out, and Claude Code **sweeps them when it starts**. Prompt history and Codex's thread index don't. An index entry with no transcript means aged out or deleted, and the age tells you which.
> - The poison sits in four places: MCP server lists, hooks, rules files (invisible Unicode) and tool descriptions, which the transcript keeps verbatim.
> - Grab the **[Agent Triage Kit](#the-agent-triage-kit)**: PowerShell, bash, KAPE, Velociraptor, Kansa, Intune, Python, Sigma and KQL, generated for the agents you pick.
{: .prompt-tip }

## Three ways an agent lands in your case

![Three ways an AI coding agent lands in your incident](/assets/images/ai-agents/agents-three-ways.svg){: w="1200" h="600" }
_Hijacked, operated by the attacker, or simply over-permissioned_

In case 2 most of the evidence sits on the attacker's machine. You see the effects: fast, tidy, machine-tempo AD enumeration through a SOCKS tunnel. Cases 1 and 3 leave the agent's whole diary on **your** endpoint, and that is what the rest of this post is about.

## The fingerprint: agents don't type

![Same command, two authors, different evidence](/assets/images/ai-agents/agents-human-vs-agent.svg){: w="1200" h="660" }
_A human leaves shell history. An agent leaves a transcript and a very particular process tree._

I ran an agent on a Windows 11 lab host, had it run a command, and captured that command from both sides: the live process table and the agent's own transcript.

![Exhibit 1: one agent-run command as the OS and the transcript saw it](/assets/images/ai-agents/agents-exhibit1-process-vs-transcript.png){: w="1600" h="1083" }
_Exhibit 1: the parent is the agent, the history is empty, the transcript has everything_

What this gives you:

- **No shell history.** The agent's shell is non-interactive, so PSReadLine and bash never record anything. Sysmon/4688 shows the process, the history is empty: think agent.
- **A wrapper you can hunt.** Claude Code's Bash tool sources `~/.claude/shell-snapshots/snapshot-bash-*.sh`, runs your command through `eval '…' < /dev/null`, then writes `pwd -P >| …/claude-XXXX-cwd`. No human types that.
- **The why.** The transcript holds the prompt, the agent's own one-line description of what it was doing, and the exact output it read back (`tool_result`).

How the other agents record a shell command:

| Agent | Launches the command as | Logged in |
| --- | --- | --- |
| Claude Code | <code>bash.exe -c "source …/.claude/shell-snapshots/… eval '&lt;cmd&gt;' &lt; /dev/null &amp;&amp; pwd -P &gt;&#124; …claude-XXXX-cwd"</code>, parent `claude.exe` | `projects/<project>/<session>.jsonl`, `tool_use` + `tool_result` |
| OpenAI Codex | `["powershell.exe", "-Command", "<cmd>"]` | `sessions/YYYY/MM/DD/rollout-*.jsonl`, `exec_command_end` with `exit_code`, `cwd`, `source: agent` |
| Cursor | `run_terminal_command_v2` | `state.vscdb` bubbles, with `createdAt` and a `rejected` flag when the human said no |

Start hunting with this in Defender XDR (the kit has four more, plus Sigma):

```sql
DeviceProcessEvents
| where ProcessCommandLine has "/.claude/shell-snapshots/snapshot-" and ProcessCommandLine has "pwd -P >|"
| extend AgentCommand = extract(@"eval '(.+)' < /dev/null", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, AgentCommand
```

## Where each agent keeps its diary

Verified on the lab host, which had seven agents installed. Copilot CLI and Gemini CLI paths come from the vendors' docs.

| Agent | Transcript | Time per record | MCP / config | Know this |
| --- | --- | --- | --- | --- |
| **Claude Code** | `~\.claude\projects\<project>\<session>.jsonl` | ✔ ms | `~\.claude.json`, `.mcp.json`, `.claude\settings*.json` | `history.jsonl` keeps every prompt; `file-history\` keeps pre-edit copies of files the agent changed |
| **OpenAI Codex** | `~\.codex\sessions\YYYY\MM\DD\rollout-*.jsonl` | ✔ | `~\.codex\config.toml` (`[mcp_servers.*]`) | `turn_context` records `approval_policy` and sandbox **per turn**; `state_5.sqlite` indexes threads |
| **Cursor** | `~\.cursor\projects\<proj>\agent-transcripts\<id>\<id>.jsonl` | ✘ none | `~\.cursor\mcp.json`, `hooks.json`, `.cursor\rules\` | Times are in `%APPDATA%\Cursor\User\globalStorage\state.vscdb` (`bubbleId:*`); `~\.cursor\ai-tracking\ai-code-tracking.db` lists files the agent **deleted** |
| **Copilot CLI** | `~\.copilot\session-state\<id>\events.jsonl` | ✔ | `~\.copilot\mcp-config.json` | `permissions-config.json` holds saved approvals per folder |
| **VS Code Copilot Chat** | `%APPDATA%\Code\User\workspaceStorage\<hash>\chatSessions\` | ✔ | `%APPDATA%\Code\User\mcp.json`, `.vscode\mcp.json` | `workspace.json` next to it maps the hash to a folder |
| **Gemini CLI** | `~\.gemini\tmp\<project-hash>\chats\` | ✔ | `~\.gemini\settings.json` | `--yolo` / `approvalMode` in settings |
| **Windsurf, Antigravity** | `~\.codeium\windsurf\cascade\*.pb`, `~\.gemini\antigravity\conversations\*.pb` | n/a | `mcp_config.json` | **Encrypted at rest** (entropy 8.0 in the lab). Pivot to the plaintext `brain\` plans, `memories\`, logs and `state.vscdb` |

> Two traps. Cursor's transcript has **no timestamps at all**, so build the timeline from `state.vscdb`. And the transcripts are plaintext: every `.env` the agent read and every secret a command printed is in there. Treat the evidence as sensitive, and the secrets as burned.
{: .prompt-warning }

## The index outlives the transcript

![The index outlives the transcript](/assets/images/ai-agents/agents-index-outlives.svg){: w="1200" h="620" }
_Retention is anti-forensics by default. Every index gives you a second chance._

Claude Code deletes transcripts older than `cleanupPeriodDays` (default 30), and the sweep runs **when the agent starts**. `~/.claude/.last-cleanup` records the last run. `history.jsonl`, the five `backups/.claude.json.*` copies (removed MCP servers stay in there) and Codex's `session_index.jsonl` and `state_5.sqlite` are not swept.

So compare the index with the transcripts. A session with no transcript that is older than the retention window aged out. One that is younger was deleted, and that is a finding.

> **Do not open the agent on a suspect host "to have a look at the history".** You will run the retention sweep yourself. Collect first.
{: .prompt-danger }

## Where the poison sits

![Where the poison sits](/assets/images/ai-agents/agents-poisoned-well.svg){: w="1200" h="640" }
_Four planted payloads in the lab repo, all benign look-alikes pointing at `.invalid` hosts_

- **MCP servers** (`.mcp.json`, `~/.claude.json`, `~/.cursor/mcp.json`, `config.toml` …): a `command` that is a shell with inline code, a download cradle, a binary in a temp folder, `npx -y` with an unpinned package, a secret in `env`.
- **Hooks**: Claude Code `settings.json` `hooks`, Cursor `hooks.json`, `~/.copilot/hooks`, Codex `notify`. They fire on every tool call. That is agent-native persistence.
- **Rules files**: `CLAUDE.md`, `AGENTS.md`, `.cursor/rules/*.mdc`, `copilot-instructions.md`. Unicode tag characters (U+E0000 to U+E007F) are invisible in editors and diffs, and the model reads them anyway. Pillar Security called it the [Rules File Backdoor](https://thehackernews.com/2025/03/new-rules-file-backdoor-attack-lets.html).
- **Tool descriptions**: Claude Code writes `api-request-shape` records holding every tool name and description it sent to the model. Hash them per session. An injection marker is your proof the model was told; a silent change between sessions is the "rug pull" Microsoft walked through in [its MCP attack write-up](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/).

Here is the kit run against that lab host:

![Exhibit 2: the Agent Triage Kit against the lab host](/assets/images/ai-agents/agents-exhibit2-triage-kit-run.png){: w="1600" h="1384" }
_Exhibit 2: 4,111 files from 7 agents in 2.5 minutes, the hidden text decoded, posture read from the sessions themselves_

## The Agent Triage Kit

Pick the platform, the agents and how you deploy. The kit writes the file in your browser; nothing is uploaded anywhere.

<div id="atk"></div>
<script src="/assets/js/agent-triage-kit.js"></script>

Prefer plain files? Here are the all-agents builds:

| File | What it does |
| --- | --- |
| [AgentTriage.ps1](/assets/files/agent-triage/AgentTriage.ps1) | Windows collector + analyzer. One ZIP with SHA256s, `findings.csv`, `agent_activity.csv`, MCP, hooks, manifest. `-Mode Inventory` to analyze in place. Live Response ready |
| [agent_triage.sh](/assets/files/agent-triage/agent_triage.sh) | macOS / Linux collector, tar.gz + manifest, runs the analyzer when `python3` is there |
| [agent_triage_analyze.py](/assets/files/agent-triage/agent_triage_analyze.py) | Offline analyzer for any collection (ZIP, tar.gz, KAPE or Velociraptor folder) or `--live`. Adds the Cursor and Codex SQLite timelines and an HTML report. Stdlib only |
| [AICodingAgents.tkape](/assets/files/agent-triage/AICodingAgents.tkape) | KAPE target |
| [Velociraptor (Windows)](/assets/files/agent-triage/Custom.Windows.Forensics.AICodingAgents.yaml) · [macOS](/assets/files/agent-triage/Custom.MacOS.Forensics.AICodingAgents.yaml) · [Linux](/assets/files/agent-triage/Custom.Linux.Forensics.AICodingAgents.yaml) | Fleet hunt: files, MCP and hook configs, Claude Code tool calls, Codex commands |
| [Get-AIAgentTriage.ps1](/assets/files/agent-triage/Get-AIAgentTriage.ps1) | Kansa module, findings as TSV per host |
| [Detect-AIAgentRisk.ps1](/assets/files/agent-triage/Detect-AIAgentRisk.ps1) | Intune remediation detection: one JSON line per device, exit 1 when it finds something |
| [ai_agent_rules.yml](/assets/files/agent-triage/ai_agent_rules.yml) · [ai_agent_hunts.kql](/assets/files/agent-triage/ai_agent_hunts.kql) | Four Sigma rules, five Defender XDR hunts |

> Tested in the lab: the PowerShell collector in all four modes (Windows PowerShell 5.1), the bash collector and the Python analyzer. The KAPE target, the Velociraptor artifacts and the Sigma rules validate as YAML but have not been run inside those tools yet. If one misbehaves, tell me in the comments and I'll fix it.
{: .prompt-info }

## Response checklist

1. **Collect before you touch the agent.** Starting it runs the retention sweep.
2. **Revoke**: the agent's own tokens (`~/.claude/.credentials.json` or the macOS Keychain, `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`), secrets in MCP `env` blocks, and every secret the transcript shows the agent read.
3. **Split the timeline by actor**: `user`, `agent`, `subagent`, `hook`. Prompts explain intent; `tool_result` shows what came back.
4. **Check every repo the agent touched**: `git log -p -- .mcp.json .claude .cursor AGENTS.md CLAUDE.md`, plus a hidden-Unicode scan.
5. **Hunt the fleet** for the same MCP server names, hook commands and decoded hidden text (Velociraptor, Intune, or the KQL above).
6. **Close it**: remove the server, hook or rules file, re-approve MCP servers, turn approvals back on, and pin it with managed settings (Claude Code: `C:\Program Files\ClaudeCode\managed-settings.json`).

## References

- Sophos: [AI used in Aur0ra ransomware testing and execution](https://www.sophos.com/en-us/blog/ai-used-in-aur0ra-ransomware-testing-and-execution)
- CloudSEK: [Caught in 4K: The Gentlemen Files](https://www.cloudsek.com/blog/caught-in-4k-the-gentlemen-files) (MCP as a command channel)
- StepSecurity: [Nx build system compromised (s1ngularity)](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware)
- Microsoft: [Securing AI agents: when AI tools move from reading to acting](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/)
- The Hacker News: [Rules File Backdoor](https://thehackernews.com/2025/03/new-rules-file-backdoor-attack-lets.html) (Pillar Security research)
- Vendor docs: [Claude Code `.claude` directory and retention](https://code.claude.com/docs/en/claude-directory), [Copilot CLI config directory](https://docs.github.com/en/enterprise-cloud@latest/copilot/reference/copilot-cli-reference/cli-config-dir-reference), [Codex configuration](https://developers.openai.com/codex/config-reference), [Cursor hooks](https://cursor.com/docs/agent/hooks)
- Related tools worth a look: SpecterOps [Blacklight](https://cybersecuritynews.com/blacklight-toolkit/) (agent artifact discovery) and [AgentDFIR](https://pkg.go.dev/github.com/efij/AgentDFIR)

---

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)

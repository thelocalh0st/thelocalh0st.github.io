#Requires -Version 5.1
<#
.SYNOPSIS
    Agent Triage Kit: collect and triage AI coding agent artifacts on Windows.

.DESCRIPTION
    Collects the transcripts, configuration, MCP server definitions, hooks and logs that
    AI coding agents leave on an endpoint, hashes every file, and writes triage findings:

      * MCP servers that launch shells, download cradles or binaries from temp folders
      * hooks and notify commands (agent-native persistence)
      * permission-bypass ("YOLO") posture, in config and in recorded sessions
      * hidden Unicode in instruction files (rules-file backdoors), decoded
      * MCP tool descriptions with injection markers, and descriptions that changed
      * sessions whose transcript is gone (deleted, purged or aged out)
      * one activity timeline of agent tool calls and user prompts

    Source files are opened read-only with shared access. Nothing on the host is changed.
    Do not open the agents on a suspect host first: Claude Code runs its retention sweep
    at startup and deletes transcripts older than cleanupPeriodDays.

    Generated 2026-10-31 by the Agent Triage Kit for: Claude Code, OpenAI Codex, Cursor, GitHub Copilot CLI, VS Code Copilot Chat, Gemini CLI, Antigravity, Windsurf, Cline. Project sweep: on.
Kansa.ps1 output directive follows
OUTPUT tsv

.PARAMETER Mode
    Collect    copy + hash + analyze, write one ZIP (default)
    Inventory  analyze in place, copy nothing, reports only
    Intune     config-only inventory; one JSON line on stdout; exit 1 when findings exist
    Kansa      inventory; findings are written to the pipeline as objects

.PARAMETER OutDir
    Output folder. Default: C:\ProgramData\AgentTriage

.PARAMETER Users
    Only these profile names (folder names under C:\Users).

.PARAMETER ProjectRoots
    Folders to sweep for repository-level agent files (.mcp.json, AGENTS.md, rules...).
    Default: every profile. Use -ProjectDepth to limit how deep the sweep goes.

.PARAMETER IncludeSecrets
    Also copy credential and token files. By default they are hashed and listed only.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\AgentTriage.ps1

.EXAMPLE
    # Microsoft Defender Live Response (upload the script to the library first)
    run AgentTriage.ps1 -parameters "-OutDir C:\ProgramData\AgentTriage"
    getfile C:\ProgramData\AgentTriage\AgentTriage_<HOST>_<UTC>.zip

.NOTES
    Agent Triage Kit by Sujay Adkesar - https://thelocalh0st.com
    License: MIT. Run elevated to cover every profile on the host.
#>
[CmdletBinding()]
param(
    [ValidateSet('Collect', 'Inventory', 'Intune', 'Kansa')]
    [string]$Mode = 'Kansa',
    [string]$OutDir,
    [string[]]$Users,
    [string[]]$ProjectRoots,
    [int]$ProjectDepth = 6,
    [switch]$IncludeSecrets,
    [int]$MaxFileMB = 1024
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$KitVersion = '1.0'
$Quiet = ($Mode -eq 'Intune') -or ($Mode -eq 'Kansa')
$Copy = $Mode -eq 'Collect'
$Deep = $Mode -ne 'Intune'
$StartUtc = [DateTime]::UtcNow

$Targets = @(
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Transcripts'; Kind = 'claude-transcript'; Base = 'Home'; Path = '.claude\projects'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Prompt history'; Kind = 'claude-history'; Base = 'Home'; Path = '.claude'; Mask = 'history.jsonl'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'File snapshots'; Kind = ''; Base = 'Home'; Path = '.claude\file-history'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Settings'; Kind = 'claude-settings'; Base = 'Home'; Path = '.claude'; Mask = 'settings.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Settings'; Kind = 'claude-settings'; Base = 'Home'; Path = '.claude'; Mask = 'settings.local.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Global state + MCP'; Kind = 'claude-global'; Base = 'Home'; Path = ''; Mask = '.claude.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Global state + MCP'; Kind = 'claude-global-backup'; Base = 'Home'; Path = '.claude\backups'; Mask = '*'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.claude'; Mask = 'CLAUDE.md'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.claude\agents'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.claude\skills'; Mask = '*.md'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.claude\commands'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.claude\rules'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Session state'; Kind = ''; Base = 'Home'; Path = '.claude\shell-snapshots'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Session state'; Kind = ''; Base = 'Home'; Path = '.claude\session-env'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Session state'; Kind = ''; Base = 'Home'; Path = '.claude\plans'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Session state'; Kind = ''; Base = 'Home'; Path = '.claude\tasks'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Session state'; Kind = ''; Base = 'Home'; Path = '.claude\todos'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Session state'; Kind = 'claude-lastcleanup'; Base = 'Home'; Path = '.claude'; Mask = '.last-cleanup'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Logs'; Kind = ''; Base = 'Home'; Path = '.claude\debug'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Plugins'; Kind = ''; Base = 'Home'; Path = '.claude\plugins'; Mask = '*.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Credentials'; Kind = ''; Base = 'Home'; Path = '.claude'; Mask = '.credentials.json'; Recurse = $false; Secret = $true }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Desktop MCP config'; Kind = 'mcp-json'; Base = 'AppData'; Path = 'Claude'; Mask = 'claude_desktop_config.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Desktop MCP config'; Kind = 'mcp-json'; Base = 'Local'; Path = 'Packages\Claude_*\LocalCache\Roaming\Claude*'; Mask = 'claude_desktop_config.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Desktop MCP logs'; Kind = ''; Base = 'AppData'; Path = 'Claude\logs'; Mask = 'mcp*.log'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Managed policy'; Kind = 'claude-settings'; Base = 'System'; Path = 'C:\Program Files\ClaudeCode'; Mask = 'managed-settings.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Claude Code'; Category = 'Managed policy'; Kind = 'mcp-json'; Base = 'System'; Path = 'C:\Program Files\ClaudeCode'; Mask = 'managed-mcp.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'Transcripts'; Kind = 'codex-rollout'; Base = 'Home'; Path = '.codex\sessions'; Mask = '*.jsonl'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'Transcripts'; Kind = 'codex-rollout'; Base = 'Home'; Path = '.codex\archived_sessions'; Mask = '*.jsonl'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'Session index'; Kind = 'codex-index'; Base = 'Home'; Path = '.codex'; Mask = 'session_index.jsonl'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'Prompt history'; Kind = ''; Base = 'Home'; Path = '.codex'; Mask = 'history.jsonl'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'State + logs DB'; Kind = ''; Base = 'Home'; Path = '.codex'; Mask = 'state_*.sqlite*'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'State + logs DB'; Kind = ''; Base = 'Home'; Path = '.codex'; Mask = 'logs_*.sqlite*'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'Config + MCP'; Kind = 'codex-config'; Base = 'Home'; Path = '.codex'; Mask = 'config.toml'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.codex'; Mask = 'AGENTS.md'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.codex\rules'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'Instructions'; Kind = ''; Base = 'Home'; Path = '.codex\memories'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'Logs'; Kind = ''; Base = 'Home'; Path = '.codex\log'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'OpenAI Codex'; Category = 'Credentials'; Kind = ''; Base = 'Home'; Path = '.codex'; Mask = 'auth.json'; Recurse = $false; Secret = $true }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Transcripts'; Kind = 'cursor-transcript'; Base = 'Home'; Path = '.cursor\projects\*\agent-transcripts'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Agent tool output'; Kind = ''; Base = 'Home'; Path = '.cursor\projects\*\agent-tools'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Agent tool output'; Kind = ''; Base = 'Home'; Path = '.cursor\projects\*\terminals'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'MCP tool cache'; Kind = 'cursor-mcpcache'; Base = 'Home'; Path = '.cursor\projects\*\mcps'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Config + MCP'; Kind = 'mcp-json'; Base = 'Home'; Path = '.cursor'; Mask = 'mcp.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Hooks'; Kind = 'hooks-json'; Base = 'Home'; Path = '.cursor'; Mask = 'hooks.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Hooks'; Kind = ''; Base = 'Home'; Path = '.cursor\hooks'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Config + MCP'; Kind = 'cursor-settings'; Base = 'Home'; Path = '.cursor'; Mask = 'cli-config.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.cursor\rules'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'AI code tracking'; Kind = ''; Base = 'Home'; Path = '.cursor\ai-tracking'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'CLI chats'; Kind = ''; Base = 'Home'; Path = '.cursor\chats'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'State DB'; Kind = ''; Base = 'AppData'; Path = 'Cursor\User\globalStorage'; Mask = 'state.vscdb*'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'State DB'; Kind = ''; Base = 'AppData'; Path = 'Cursor\User\workspaceStorage\*'; Mask = 'state.vscdb*'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'State DB'; Kind = ''; Base = 'AppData'; Path = 'Cursor\User\workspaceStorage\*'; Mask = 'workspace.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Config + MCP'; Kind = 'cursor-settings'; Base = 'AppData'; Path = 'Cursor\User'; Mask = 'settings.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Config + MCP'; Kind = 'mcp-json'; Base = 'AppData'; Path = 'Cursor\User'; Mask = 'mcp.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Cursor'; Category = 'Logs'; Kind = ''; Base = 'AppData'; Path = 'Cursor\logs'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Transcripts'; Kind = 'copilot-events'; Base = 'Home'; Path = '.copilot\session-state'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Transcripts'; Kind = 'copilot-events'; Base = 'Home'; Path = '.copilot\history-session-state'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Session index'; Kind = ''; Base = 'Home'; Path = '.copilot'; Mask = 'session-store.db*'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Prompt history'; Kind = ''; Base = 'Home'; Path = '.copilot\command-history-state'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Config + MCP'; Kind = 'mcp-json'; Base = 'Home'; Path = '.copilot'; Mask = 'mcp-config.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Config + MCP'; Kind = ''; Base = 'Home'; Path = '.copilot'; Mask = 'config.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Config + MCP'; Kind = 'hooks-json'; Base = 'Home'; Path = '.copilot'; Mask = 'settings.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Saved approvals'; Kind = 'copilot-perms'; Base = 'Home'; Path = '.copilot'; Mask = 'permissions-config.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Hooks'; Kind = 'hook-script'; Base = 'Home'; Path = '.copilot\hooks'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.copilot'; Mask = 'copilot-instructions.md'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.copilot\agents'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.copilot\instructions'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Logs'; Kind = ''; Base = 'Home'; Path = '.copilot\logs'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'GitHub Copilot CLI'; Category = 'Credentials'; Kind = ''; Base = 'Home'; Path = '.copilot\mcp-oauth-config'; Mask = '*'; Recurse = $true; Secret = $true }
    [pscustomobject]@{ Agent = 'VS Code Copilot Chat'; Category = 'Transcripts'; Kind = ''; Base = 'AppData'; Path = 'Code\User\workspaceStorage\*\chatSessions'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'VS Code Copilot Chat'; Category = 'Transcripts'; Kind = ''; Base = 'AppData'; Path = 'Code\User\workspaceStorage\*\chatEditingSessions'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'VS Code Copilot Chat'; Category = 'Transcripts'; Kind = ''; Base = 'AppData'; Path = 'Code\User\globalStorage\emptyWindowChatSessions'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'VS Code Copilot Chat'; Category = 'State DB'; Kind = ''; Base = 'AppData'; Path = 'Code\User\workspaceStorage\*'; Mask = 'workspace.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'VS Code Copilot Chat'; Category = 'Config + MCP'; Kind = 'mcp-json'; Base = 'AppData'; Path = 'Code\User'; Mask = 'mcp.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'VS Code Copilot Chat'; Category = 'Config + MCP'; Kind = ''; Base = 'AppData'; Path = 'Code\User'; Mask = 'settings.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'VS Code Copilot Chat'; Category = 'Logs'; Kind = ''; Base = 'AppData'; Path = 'Code\logs'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Gemini CLI'; Category = 'Transcripts'; Kind = 'gemini-chat'; Base = 'Home'; Path = '.gemini\tmp'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Gemini CLI'; Category = 'Config + MCP'; Kind = 'gemini-settings'; Base = 'Home'; Path = '.gemini'; Mask = 'settings.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Gemini CLI'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.gemini'; Mask = 'GEMINI.md'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Gemini CLI'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.gemini\commands'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Gemini CLI'; Category = 'Extensions'; Kind = 'mcp-json'; Base = 'Home'; Path = '.gemini\extensions'; Mask = 'gemini-extension.json'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Gemini CLI'; Category = 'Credentials'; Kind = ''; Base = 'Home'; Path = '.gemini'; Mask = 'oauth_creds.json'; Recurse = $false; Secret = $true }
    [pscustomobject]@{ Agent = 'Gemini CLI'; Category = 'Credentials'; Kind = ''; Base = 'Home'; Path = '.gemini'; Mask = 'google_accounts.json'; Recurse = $false; Secret = $true }
    [pscustomobject]@{ Agent = 'Antigravity'; Category = 'Config + MCP'; Kind = 'mcp-json'; Base = 'Home'; Path = '.gemini\antigravity'; Mask = 'mcp_config.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Antigravity'; Category = 'Transcripts'; Kind = 'antigravity'; Base = 'Home'; Path = '.gemini\antigravity'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Antigravity'; Category = 'State DB'; Kind = ''; Base = 'AppData'; Path = 'Antigravity\User\globalStorage'; Mask = 'state.vscdb*'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Antigravity'; Category = 'State DB'; Kind = ''; Base = 'AppData'; Path = 'Antigravity\User\workspaceStorage\*'; Mask = 'state.vscdb*'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Antigravity'; Category = 'State DB'; Kind = ''; Base = 'AppData'; Path = 'Antigravity\User\workspaceStorage\*'; Mask = 'workspace.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Antigravity'; Category = 'Config + MCP'; Kind = ''; Base = 'AppData'; Path = 'Antigravity\User'; Mask = 'settings.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Antigravity'; Category = 'Logs'; Kind = ''; Base = 'AppData'; Path = 'Antigravity\logs'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Windsurf'; Category = 'Config + MCP'; Kind = 'mcp-json'; Base = 'Home'; Path = '.codeium\windsurf'; Mask = 'mcp_config.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Windsurf'; Category = 'Instructions'; Kind = 'instructions'; Base = 'Home'; Path = '.codeium\windsurf\memories'; Mask = '*.md'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Windsurf'; Category = 'Transcripts'; Kind = 'windsurf'; Base = 'Home'; Path = '.codeium\windsurf'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Windsurf'; Category = 'State DB'; Kind = ''; Base = 'AppData'; Path = 'Windsurf\User\globalStorage'; Mask = 'state.vscdb*'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Windsurf'; Category = 'State DB'; Kind = ''; Base = 'AppData'; Path = 'Windsurf\User\workspaceStorage\*'; Mask = 'state.vscdb*'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Windsurf'; Category = 'State DB'; Kind = ''; Base = 'AppData'; Path = 'Windsurf\User\workspaceStorage\*'; Mask = 'workspace.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Windsurf'; Category = 'Config + MCP'; Kind = ''; Base = 'AppData'; Path = 'Windsurf\User'; Mask = 'settings.json'; Recurse = $false; Secret = $false }
    [pscustomobject]@{ Agent = 'Windsurf'; Category = 'Logs'; Kind = ''; Base = 'AppData'; Path = 'Windsurf\logs'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cline'; Category = 'Transcripts'; Kind = ''; Base = 'AppData'; Path = 'Code\User\globalStorage\saoudrizwan.claude-dev\tasks'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cline'; Category = 'Config + MCP'; Kind = 'mcp-json'; Base = 'AppData'; Path = 'Code\User\globalStorage\saoudrizwan.claude-dev\settings'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cline'; Category = 'Transcripts'; Kind = ''; Base = 'AppData'; Path = 'Cursor\User\globalStorage\saoudrizwan.claude-dev\tasks'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cline'; Category = 'Config + MCP'; Kind = 'mcp-json'; Base = 'AppData'; Path = 'Cursor\User\globalStorage\saoudrizwan.claude-dev\settings'; Mask = '*'; Recurse = $true; Secret = $false }
    [pscustomobject]@{ Agent = 'Cline'; Category = 'Transcripts'; Kind = ''; Base = 'Home'; Path = '.cline'; Mask = '*'; Recurse = $true; Secret = $false }
)
$ProjectSweep = $true
$ProjectFiles = @(
    [pscustomobject]@{ Name = '.mcp.json'; Ext = ''; Parent = @(); Kind = 'mcp-json' }
    [pscustomobject]@{ Name = 'mcp.json'; Ext = ''; Parent = @('.vscode', '.cursor', '.github'); Kind = 'mcp-json' }
    [pscustomobject]@{ Name = 'settings.json'; Ext = ''; Parent = @('.claude'); Kind = 'claude-settings' }
    [pscustomobject]@{ Name = 'settings.local.json'; Ext = ''; Parent = @('.claude'); Kind = 'claude-settings' }
    [pscustomobject]@{ Name = 'settings.json'; Ext = ''; Parent = @('.gemini'); Kind = 'gemini-settings' }
    [pscustomobject]@{ Name = 'hooks.json'; Ext = ''; Parent = @('.cursor'); Kind = 'hooks-json' }
    [pscustomobject]@{ Name = 'config.toml'; Ext = ''; Parent = @('.codex'); Kind = 'codex-config' }
    [pscustomobject]@{ Name = 'CLAUDE.md'; Ext = ''; Parent = @(); Kind = 'instructions' }
    [pscustomobject]@{ Name = 'CLAUDE.local.md'; Ext = ''; Parent = @(); Kind = 'instructions' }
    [pscustomobject]@{ Name = 'AGENTS.md'; Ext = ''; Parent = @(); Kind = 'instructions' }
    [pscustomobject]@{ Name = 'GEMINI.md'; Ext = ''; Parent = @(); Kind = 'instructions' }
    [pscustomobject]@{ Name = '.cursorrules'; Ext = ''; Parent = @(); Kind = 'instructions' }
    [pscustomobject]@{ Name = '.windsurfrules'; Ext = ''; Parent = @(); Kind = 'instructions' }
    [pscustomobject]@{ Name = '.clinerules'; Ext = ''; Parent = @(); Kind = 'instructions' }
    [pscustomobject]@{ Name = 'copilot-instructions.md'; Ext = ''; Parent = @(); Kind = 'instructions' }
    [pscustomobject]@{ Name = 'SKILL.md'; Ext = ''; Parent = @(); Kind = 'instructions' }
    [pscustomobject]@{ Name = ''; Ext = '.mdc'; Parent = @('rules'); Kind = 'instructions' }
    [pscustomobject]@{ Name = ''; Ext = '.instructions.md'; Parent = @(); Kind = 'instructions' }
)
$SkipDirs = @('AppData', 'Library', 'node_modules', '.git', '.venv', 'venv', '__pycache__', '.cache', '.npm', '.nuget', '.gradle', '.m2', '.cargo', '.rustup', 'go', 'scoop', '$Recycle.Bin', '.Trash', '.vscode-server')
$SkipPairs = @('.claude/projects', '.claude/file-history', '.claude/plugins', '.codex/sessions', '.codex/plugins', '.cursor/projects', '.cursor/extensions', '.vscode/extensions', '.gemini/antigravity', '.gemini/tmp', '.codeium/windsurf')

function Say([string]$Text, [string]$Color = 'Gray') { if (-not $Quiet) { Write-Host $Text -ForegroundColor $Color } }

#region helpers ---------------------------------------------------------------------------
function LongPath([string]$Path) {
    if ($Path.Length -ge 240 -and -not $Path.StartsWith('\\?\')) { return '\\?\' + $Path }
    return $Path
}
function Unprefix([string]$Path) { if ($Path.StartsWith('\\?\')) { return $Path.Substring(4) } return $Path }

function Open-Shared([string]$Path) {
    [IO.File]::Open((LongPath $Path), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
}

function Read-SharedText([string]$Path, [int]$MaxBytes = 33554432) {
    $fs = $null
    try {
        $fs = Open-Shared $Path
        if ($fs.Length -gt $MaxBytes) { return $null }
        $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8, $true)
        return $sr.ReadToEnd()
    } catch { return $null } finally { if ($fs) { $fs.Dispose() } }
}

function Get-SharedHash([string]$Path) {
    $fs = $null
    try {
        $fs = Open-Shared $Path
        $sha = [Security.Cryptography.SHA256]::Create()
        return ([BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '')
    } catch { return '' } finally { if ($fs) { $fs.Dispose() } }
}

function ConvertFrom-JsonLoose([string]$Text) {
    if (-not $Text) { return $null }
    $t = $Text -replace '(?m)^\s*//.*$', ''
    $t = $t -replace ',(\s*[}\]])', '$1'
    try { return ($t | ConvertFrom-Json -ErrorAction Stop) } catch { return $null }
}

function Trunc([string]$Text, [int]$Max = 300) {
    if ($null -eq $Text) { return '' }
    $t = ($Text -replace '[\r\n\t]+', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max) + '...' }
    return $t
}

function Get-Prop($Obj, [string]$Name) {
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Expand-WildPath([string]$Path) {
    $parts = $Path -split '\\'
    $cur = @($parts[0] + '\')
    for ($i = 1; $i -lt $parts.Count; $i++) {
        $seg = $parts[$i]
        if (-not $seg) { continue }
        $next = @()
        foreach ($c in $cur) {
            if ($seg -match '[\*\?]') {
                try { $next += @([IO.Directory]::GetDirectories((LongPath $c), $seg) | ForEach-Object { Unprefix $_ }) } catch { }
            } else {
                $p = [IO.Path]::Combine($c, $seg)
                if ([IO.Directory]::Exists((LongPath $p))) { $next += $p }
            }
        }
        $cur = $next
        if (-not $cur) { return @() }
    }
    return $cur
}

function Get-FilesIn([string]$Dir, [string]$Mask, [bool]$Recurse) {
    $stack = New-Object System.Collections.Stack
    $stack.Push($Dir)
    while ($stack.Count -gt 0) {
        $d = $stack.Pop()
        try { foreach ($f in [IO.Directory]::GetFiles((LongPath $d), $Mask)) { New-Object IO.FileInfo($f) } } catch { }
        if ($Recurse) {
            try { foreach ($s in [IO.Directory]::GetDirectories((LongPath $d))) { $stack.Push((Unprefix $s)) } } catch { }
        }
    }
}

function Resolve-TargetRoot($T, [string]$ProfilePath) {
    $rel = $T.Path
    switch ($T.Base) {
        'Home' { $base = $ProfilePath }
        'AppData' { $base = Join-Path $ProfilePath 'AppData\Roaming' }
        'Local' { $base = Join-Path $ProfilePath 'AppData\Local' }
        'System' { return $T.Path }
        default { return $null }
    }
    if (-not $rel) { return $base }
    return (Join-Path $base $rel)
}

$SevRank = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2; 'Info' = 3 }
$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Severity, [string]$Agent, [string]$User, [string]$Title, [string]$Detail, [string]$Source) {
    $Findings.Add([pscustomobject]@{
            Severity = $Severity; Agent = $Agent; User = $User; Finding = $Title
            Detail = (Trunc $Detail 600); Source = $Source
        })
}
#endregion

#region detection logic --------------------------------------------------------------------
$RxCradle = '(?i)(\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-bitstransfer|\bcurl(\.exe)?\s|\bwget\s|certutil(\.exe)?\s.*urlcache|bitsadmin|frombase64string|\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{16,}|\|\s*(ba|z)?sh\b|\|\s*iex\b|invoke-expression|\bnc(at)?\s+-e)'
$RxShell = '(?i)(^|[\\/])(powershell|pwsh|cmd|bash|sh|zsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?$'
$RxInline = '(?i)^(-c|-command|/c|/k|-e|-enc|-encodedcommand|-lc)$'
$RxTemp = '(?i)(\\temp\\|\\tmp\\|/tmp/|\\downloads\\|/downloads/|\\users\\public\\|\\programdata\\[^\\]+\.exe)'
$RxRunner = '(?i)(^|[\\/])(npx|bunx|uvx|pnpx)(\.cmd|\.exe)?$'
$RxSecretName = '(?i)(token|secret|passw|api[_-]?key|access[_-]?key|private[_-]?key|\bpat\b|auth)'
$RxInjectWeak = '(?i)(do not|don''t|never) (tell|inform|mention|reveal|narrate|show)[^.\n]{0,40}user'
$RxInject = '(?i)(ignore (all |any )?(previous|prior|above) instructions|<\s*/?\s*(important|system|secret|instructions?)\s*>|before (using|calling|invoking) (this|any other|any) tool|[\\/]\.ssh[\\/]|id_rsa|\.aws[\\/]credentials|wallet\.dat|\bseed phrase|send (it|them|the (file|contents?|output)) to|exfiltrat)'
$RxHidden = '[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069]|\uDB40[\uDC00-\uDC7F]'

function Get-HiddenUnicode([string]$Text) {
    if (-not $Text) { return $null }
    $body = $Text
    if ($body.Length -gt 0 -and $body[0] -eq [char]0xFEFF) { $body = $body.Substring(1) }
    $ms = [regex]::Matches($body, $RxHidden)
    $bom = ([regex]::Matches($body, '\uFEFF')).Count
    if ($ms.Count -eq 0 -and $bom -eq 0) { return $null }
    $kinds = @{}
    $tagText = New-Object Text.StringBuilder
    foreach ($m in $ms) {
        $v = $m.Value
        if ($v.Length -eq 2) {
            $cp = [char]::ConvertToUtf32($v[0], $v[1])
            $kinds['tag'] = 1
            $c = $cp - 0xE0000
            if ($c -ge 0x20 -and $c -le 0x7E) { [void]$tagText.Append([char]$c) }
        } else {
            $cp = [int][char]$v
            if ($cp -ge 0x202A -and $cp -le 0x202E -or ($cp -ge 0x2066 -and $cp -le 0x2069)) { $kinds['bidi'] = 1 } else { $kinds['zero-width'] = 1 }
        }
    }
    if ($bom -gt 0) { $kinds['inner-BOM'] = 1 }
    [pscustomobject]@{
        Count   = $ms.Count + $bom
        Kinds   = ($kinds.Keys | Sort-Object) -join ','
        Decoded = $tagText.ToString()
        Severe  = [bool]($kinds['tag'] -or $kinds['bidi'])
    }
}

function Get-McpFlags([string]$Command, [string[]]$Arguments, [string]$Url, $Env) {
    $flags = New-Object System.Collections.Generic.List[string]
    $sev = 'Info'
    $all = (@($Command) + @($Arguments)) -join ' '
    if ($Command -and ($Command -match $RxShell)) {
        $inline = @($Arguments | Where-Object { $_ -match $RxInline }).Count -gt 0
        if ($inline) { $flags.Add('shell-inline-code'); $sev = 'High' } else { $flags.Add('shell-launcher'); if ($sev -ne 'High') { $sev = 'Medium' } }
    }
    if ($all -match $RxCradle) { $flags.Add('download-or-decode'); $sev = 'High' }
    if ($Command -and ($Command -match $RxTemp)) { $flags.Add('binary-in-temp-or-public'); $sev = 'High' }
    if ($Command -and ($Command -match $RxRunner)) {
        $pkg = @($Arguments | Where-Object { $_ -and -not $_.StartsWith('-') }) | Select-Object -First 1
        if ($pkg -and ($pkg -notmatch '^@?[^@]+@\d') ) { $flags.Add('unpinned-package:' + $pkg); if ($sev -eq 'Info') { $sev = 'Low' } }
    }
    if ($Url) {
        try { $h = ([Uri]$Url).Host } catch { $h = $Url }
        if ($h -notmatch '^(localhost|127\.0\.0\.1|\[::1\]|::1)$') { $flags.Add('remote:' + $h) }
    }
    if ($Env) {
        foreach ($p in $Env.PSObject.Properties) {
            $val = [string]$p.Value
            if ($p.Name -match $RxSecretName -and $val.Length -ge 12 -and $val -notmatch '^\$|^%|^\{\{|^<|^\$\{') {
                $flags.Add('plaintext-secret:' + $p.Name); if ($sev -eq 'Info' -or $sev -eq 'Low') { $sev = 'Medium' }
            }
        }
    }
    [pscustomobject]@{ Flags = ($flags -join '; '); Severity = $sev }
}
#endregion

#region discovery -----------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$profiles = @()
if ($isAdmin) {
    $profiles = @(Get-CimInstance Win32_UserProfile -Filter 'Special = False' | ForEach-Object { $_.LocalPath } |
        Where-Object { $_ -and [IO.Directory]::Exists($_) })
}
if (-not $profiles) { $profiles = @($env:USERPROFILE) }
if ($Users) { $profiles = @($profiles | Where-Object { $Users -contains (Split-Path $_ -Leaf) }) }

Say ''
Say '  Agent Triage Kit  |  AI coding agent forensics for Windows' 'Cyan'
Say ('  host {0}  |  mode {1}  |  elevated {2}  |  profiles {3}' -f $env:COMPUTERNAME, $Mode, $isAdmin, $profiles.Count) 'DarkGray'
if (-not $isAdmin) { Say '  Not elevated: only the current profile is covered.' 'Yellow' }

$Hits = New-Object System.Collections.Generic.List[object]
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
function Add-Hit($Fi, [string]$Agent, [string]$Category, [string]$Kind, [bool]$Secret, [string]$User, [string]$ProfilePath) {
    $full = Unprefix $Fi.FullName
    if (-not $seen.Add($full)) { return }
    $Hits.Add([pscustomobject]@{
            User = $User; Agent = $Agent; Category = $Category; Kind = $Kind; Secret = $Secret
            Path = $full; Info = $Fi; Profile = $ProfilePath
        })
}

foreach ($prof in $profiles) {
    $user = Split-Path $prof -Leaf
    foreach ($t in $Targets) {
        if ($t.Base -eq 'System') { continue }
        if (-not $Deep -and $t.Category -in @('Transcripts', 'Logs', 'Agent tool output', 'File snapshots', 'State DB', 'State + logs DB', 'Session state')) { continue }
        $root = Resolve-TargetRoot $t $prof
        if (-not $root) { continue }
        foreach ($d in (Expand-WildPath $root)) {
            foreach ($fi in (Get-FilesIn $d $t.Mask $t.Recurse)) { Add-Hit $fi $t.Agent $t.Category $t.Kind $t.Secret $user $prof }
        }
    }
}
foreach ($t in @($Targets | Where-Object { $_.Base -eq 'System' })) {
    foreach ($d in (Expand-WildPath $t.Path)) {
        foreach ($fi in (Get-FilesIn $d $t.Mask $false)) { Add-Hit $fi $t.Agent $t.Category $t.Kind $t.Secret 'SYSTEM' '' }
    }
}

# repository-level agent files (.mcp.json, AGENTS.md, .cursor/rules ...)
function Get-ProjectKind([string]$Name, [string]$Parent) {
    $n = $Name.ToLowerInvariant(); $p = $Parent.ToLowerInvariant()
    foreach ($r in $ProjectFiles) {
        if ($r.Parent -and -not ($r.Parent -contains $p)) { continue }
        if ($r.Name -and $n -eq $r.Name.ToLowerInvariant()) { return $r.Kind }
        if ($r.Ext -and $n.EndsWith($r.Ext.ToLowerInvariant())) { return $r.Kind }
    }
    return $null
}
if ($ProjectSweep -and $Deep) {
    $roots = if ($ProjectRoots) { $ProjectRoots } else { $profiles }
    foreach ($root in $roots) {
        $owner = if ($root -like 'C:\Users\*') { ($root -split '\\')[2] } else { 'project' }
        $queue = New-Object System.Collections.Queue
        $queue.Enqueue(@($root, 0))
        while ($queue.Count -gt 0) {
            $item = $queue.Dequeue(); $dir = $item[0]; $depth = $item[1]
            $parent = Split-Path $dir -Leaf
            try {
                foreach ($f in [IO.Directory]::GetFiles((LongPath $dir))) {
                    $fi = New-Object IO.FileInfo($f)
                    if ($fi.Length -gt 5MB) { continue }
                    $k = Get-ProjectKind $fi.Name $parent
                    if ($k) { Add-Hit $fi 'Project files' 'Repository config' $k $false $owner '' }
                }
            } catch { }
            if ($depth -ge $ProjectDepth) { continue }
            try {
                foreach ($s in [IO.Directory]::GetDirectories((LongPath $dir))) {
                    $s = Unprefix $s
                    $leaf = Split-Path $s -Leaf
                    if ($SkipDirs -contains $leaf) { continue }
                    if ($SkipPairs -contains ($parent + '/' + $leaf)) { continue }
                    $attr = [IO.File]::GetAttributes((LongPath $s))
                    if ($attr -band [IO.FileAttributes]::ReparsePoint) { continue }
                    $queue.Enqueue(@($s, ($depth + 1)))
                }
            } catch { }
        }
    }
}
Say ('  found {0} artifact files' -f $Hits.Count) 'DarkGray'
#endregion

#region collection ----------------------------------------------------------------------------
$stamp = $StartUtc.ToString('yyyyMMddTHHmmssZ')
$caseName = 'AgentTriage_{0}_{1}' -f $env:COMPUTERNAME, $stamp
if (-not $OutDir) { $OutDir = Join-Path $env:ProgramData 'AgentTriage' }
$repDir = Join-Path (Join-Path $OutDir $caseName) 'report'
if (-not $Quiet) {
    try { [void][IO.Directory]::CreateDirectory($repDir) } catch {
        $OutDir = Join-Path $env:TEMP 'AgentTriage'; $repDir = Join-Path (Join-Path $OutDir $caseName) 'report'
        [void][IO.Directory]::CreateDirectory($repDir)
    }
}

$Manifest = New-Object System.Collections.Generic.List[object]
$zip = $null; $zipPath = $null
if ($Copy) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipPath = Join-Path $OutDir ($caseName + '.zip')
    $zipStream = [IO.File]::Open($zipPath, [IO.FileMode]::Create)
    $zip = New-Object IO.Compression.ZipArchive($zipStream, [IO.Compression.ZipArchiveMode]::Create)
}
$maxBytes = [int64]$MaxFileMB * 1MB
$buffer = New-Object byte[] 1048576
$n = 0
foreach ($h in $Hits) {
    $n++
    if ($Copy -and ($n % 250 -eq 0)) { Say ('  collecting {0}/{1}' -f $n, $Hits.Count) 'DarkGray' }
    $fi = $h.Info; $sha = ''; $collected = $false; $note = ''
    if ($Mode -eq 'Intune') { continue }
    if ($fi.Length -gt $maxBytes) { $note = 'over size limit, not hashed' }
    elseif ($Copy -and -not ($h.Secret -and -not $IncludeSecrets)) {
        $entryName = 'evidence/' + (($h.Path -replace '^([A-Za-z]):', '$1') -replace '\\', '/')
        $src = $null; $dst = $null
        try {
            $src = Open-Shared $h.Path
            $entry = $zip.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
            try { $entry.LastWriteTime = [DateTimeOffset]$fi.LastWriteTime } catch { }
            $dst = $entry.Open()
            $hasher = [Security.Cryptography.SHA256]::Create()
            while (($read = $src.Read($buffer, 0, $buffer.Length)) -gt 0) {
                [void]$hasher.TransformBlock($buffer, 0, $read, $null, 0)
                $dst.Write($buffer, 0, $read)
            }
            [void]$hasher.TransformFinalBlock($buffer, 0, 0)
            $sha = ([BitConverter]::ToString($hasher.Hash)).Replace('-', '')
            $collected = $true
        } catch { $note = 'copy failed: ' + $_.Exception.Message } finally { if ($dst) { $dst.Dispose() }; if ($src) { $src.Dispose() } }
    } elseif ($Copy -or $h.Secret) {
        $sha = Get-SharedHash $h.Path
        if ($h.Secret) { $note = 'credential file: hashed, not copied' }
    }
    $Manifest.Add([pscustomobject]@{
            User = $h.User; Agent = $h.Agent; Category = $h.Category; Path = $h.Path; Size = $fi.Length
            CreatedUtc = $fi.CreationTimeUtc.ToString('o'); ModifiedUtc = $fi.LastWriteTimeUtc.ToString('o')
            AccessedUtc = $fi.LastAccessTimeUtc.ToString('o'); SHA256 = $sha; Collected = $collected; Note = $note
        })
}
#endregion

#region analysis ------------------------------------------------------------------------------
$McpRows = New-Object System.Collections.Generic.List[object]
$HookRows = New-Object System.Collections.Generic.List[object]
$Activity = New-Object System.Collections.Generic.List[object]
$ToolsSeen = @{}

function Add-Activity($Ts, [string]$Agent, [string]$User, [string]$Session, [string]$Actor, [string]$Tool, [string]$Detail, [string]$Cwd, [string]$Source) {
    $Activity.Add([pscustomobject]@{
            TimestampUtc = [string]$Ts; Agent = $Agent; User = $User; Session = $Session; Actor = $Actor
            Tool = $Tool; Detail = (Trunc $Detail 400); Cwd = $Cwd; Source = $Source
        })
}

function Add-McpServer([string]$Agent, [string]$User, [string]$Source, [string]$Scope, [string]$Name, $Def) {
    $cmd = [string](Get-Prop $Def 'command')
    $argv = @(Get-Prop $Def 'args' | ForEach-Object { [string]$_ })
    $url = [string](Get-Prop $Def 'url'); if (-not $url) { $url = [string](Get-Prop $Def 'serverUrl') }; if (-not $url) { $url = [string](Get-Prop $Def 'httpUrl') }
    $envObj = Get-Prop $Def 'env'
    $transport = [string](Get-Prop $Def 'type'); if (-not $transport) { $transport = if ($url) { 'http' } else { 'stdio' } }
    $risk = Get-McpFlags $cmd $argv $url $envObj
    $envNames = if ($envObj) { ($envObj.PSObject.Properties | ForEach-Object { $_.Name }) -join ',' } else { '' }
    $McpRows.Add([pscustomobject]@{
            Agent = $Agent; User = $User; Server = $Name; Transport = $transport; Command = $cmd; Args = (Trunc ($argv -join ' ') 400)
            Url = $url; EnvNames = $envNames; Severity = $risk.Severity; Flags = $risk.Flags; Scope = $Scope; Source = $Source
        })
    if ($risk.Severity -in @('High', 'Medium')) {
        Add-Finding $risk.Severity $Agent $User ("MCP server '{0}' looks risky" -f $Name) ("{0} | {1} {2} {3}" -f $risk.Flags, $cmd, ($argv -join ' '), $url) $Source
    }
}

function Find-McpServers($Node, [string]$Trail, [int]$Depth, [bool]$VsCodeStyle, $Acc) {
    if ($null -eq $Node -or $Depth -gt 6) { return }
    if ($Node -is [Management.Automation.PSCustomObject]) {
        foreach ($p in $Node.PSObject.Properties) {
            $isMap = $p.Value -is [Management.Automation.PSCustomObject]
            if ($isMap -and ($p.Name -eq 'mcpServers' -or $p.Name -eq 'mcp_servers' -or ($VsCodeStyle -and $p.Name -eq 'servers'))) {
                foreach ($s in $p.Value.PSObject.Properties) { $Acc.Add(@($Trail, $s.Name, $s.Value)) }
            } elseif ($p.Value -is [Management.Automation.PSCustomObject] -or $p.Value -is [Array]) {
                Find-McpServers $p.Value ($Trail + '/' + $p.Name) ($Depth + 1) $VsCodeStyle $Acc
            }
        }
    } elseif ($Node -is [Array]) { foreach ($i in $Node) { Find-McpServers $i $Trail ($Depth + 1) $VsCodeStyle $Acc } }
}

function Get-HookCommands($Node, [string]$Event, $Acc) {
    if ($null -eq $Node) { return }
    if ($Node -is [Array]) { foreach ($i in $Node) { Get-HookCommands $i $Event $Acc }; return }
    if ($Node -is [Management.Automation.PSCustomObject]) {
        foreach ($k in @('command', 'bash', 'powershell', 'cmd')) {
            $v = Get-Prop $Node $k
            if ($v -is [string] -and $v) { $Acc.Add(@($Event, $v)) }
        }
        foreach ($p in $Node.PSObject.Properties) {
            if ($p.Value -is [Management.Automation.PSCustomObject] -or $p.Value -is [Array]) {
                $ev = if ($Event) { $Event } else { $p.Name }
                Get-HookCommands $p.Value $ev $Acc
            }
        }
    }
}

function Add-Hooks([string]$Agent, [string]$User, [string]$Source, $HooksNode) {
    $acc = New-Object System.Collections.Generic.List[object]
    Get-HookCommands $HooksNode '' $acc
    foreach ($a in $acc) {
        $sev = 'Low'; $fl = ''
        if ($a[1] -match $RxCradle) { $sev = 'High'; $fl = 'download-or-decode' }
        elseif ($a[1] -match $RxTemp) { $sev = 'High'; $fl = 'binary-in-temp-or-public' }
        $HookRows.Add([pscustomobject]@{ Agent = $Agent; User = $User; Event = $a[0]; Command = (Trunc $a[1] 500); Severity = $sev; Flags = $fl; Source = $Source })
        $title = if ($sev -eq 'High') { 'Agent hook runs a download/decode command' } else { 'Agent hook configured' }
        Add-Finding $sev $Agent $User $title ("{0}: {1}" -f $a[0], $a[1]) $Source
    }
}

function Test-ToolDescription([string]$Agent, [string]$User, [string]$Tool, [string]$Desc, [string]$Ts, [string]$Session, [string]$Source) {
    if (-not $Desc) { return }
    $sha = [BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes($Desc))).Replace('-', '').Substring(0, 16)
    $key = $Agent + '|' + $User + '|' + $Tool
    if (-not $ToolsSeen.ContainsKey($key)) { $ToolsSeen[$key] = @{ Agent = $Agent; User = $User; Tool = $Tool; Hashes = @{}; First = $Ts; Last = $Ts; Flags = '' } }
    $e = $ToolsSeen[$key]
    if ($Ts -and (-not $e.First -or $Ts -lt $e.First)) { $e.First = $Ts }
    if ($Ts -and $Ts -gt $e.Last) { $e.Last = $Ts }
    if ($e.Hashes.ContainsKey($sha)) { return }
    $flags = ''
    $hid = Get-HiddenUnicode $Desc
    $strong = [regex]::Match($Desc, $RxInject)
    $weak = [regex]::Match($Desc, $RxInjectWeak)
    if ($hid -or $strong.Success -or $weak.Success) {
        $why = @()
        if ($strong.Success) { $why += ("injection marker '{0}'" -f $strong.Value) }
        if ($weak.Success) { $why += ("hides activity from the user: '{0}'" -f $weak.Value) }
        if ($hid) { $why += ("hidden Unicode ({0}) {1}" -f $hid.Kinds, $hid.Decoded) }
        $flags = $why -join '; '
        $sev = if ($strong.Success -or ($hid -and $hid.Severe)) { 'High' } else { 'Medium' }
        Add-Finding $sev $Agent $User ("Tool description seen by the model looks poisoned: {0}" -f $Tool) ($flags + ' | ' + $Desc) $Source
    }
    $e.Hashes[$sha] = [pscustomobject]@{ Ts = $Ts; Session = $Session; Source = $Source; Flags = $flags; Desc = $Desc }
}

$byKind = @{}
foreach ($h in $Hits) { if ($h.Kind) { if (-not $byKind.ContainsKey($h.Kind)) { $byKind[$h.Kind] = New-Object System.Collections.Generic.List[object] }; $byKind[$h.Kind].Add($h) } }
function Get-Kind([string]$Kind) { if ($byKind.ContainsKey($Kind)) { return $byKind[$Kind] } return @() }
$TextExt = '(?i)\.(md|mdc|txt|json|jsonc|toml|ya?ml|rules|instructions)$|(^|[\\/])\.(cursorrules|windsurfrules|clinerules)$'

Say '  analyzing ...' 'DarkGray'

# MCP definitions: JSON configs, Claude global state, Gemini settings, Codex TOML
foreach ($h in @(Get-Kind 'mcp-json') + @(Get-Kind 'claude-global') + @(Get-Kind 'gemini-settings')) {
    if ($h.Info.Length -gt 33554432) { continue }
    $text = Read-SharedText $h.Path
    $obj = ConvertFrom-JsonLoose $text
    if (-not $obj) { continue }
    $acc = New-Object System.Collections.Generic.List[object]
    $vs = $h.Info.Name -ieq 'mcp.json'
    Find-McpServers $obj '' 0 $vs $acc
    foreach ($a in $acc) { Add-McpServer $h.Agent $h.User $h.Path ($(if ($a[0]) { $a[0] } else { 'user' })) $a[1] $a[2] }
    $hooks = Get-Prop $obj 'hooks'
    if ($hooks -and $h.Kind -eq 'gemini-settings') { Add-Hooks $h.Agent $h.User $h.Path $hooks }
    if ($h.Kind -eq 'gemini-settings' -and $text -match '(?i)"(yolo|autoAccept)"\s*:\s*true|"approvalMode"\s*:\s*"yolo"') {
        Add-Finding 'Medium' $h.Agent $h.User 'Gemini CLI auto-approves tool calls (YOLO)' $Matches[0] $h.Path
    }
}

foreach ($h in Get-Kind 'codex-config') {
    $text = Read-SharedText $h.Path
    if (-not $text) { continue }
    $section = ''; $srv = $null
    $servers = [ordered]@{}
    foreach ($line in ($text -split "`r?`n")) {
        $l = $line.Trim()
        if ($l -match '^\[(.+)\]$') {
            $section = $Matches[1]
            $srv = $null
            if ($section -match '^mcp_servers\."?([^".]+)"?$') { $srv = $Matches[1]; $servers[$srv] = [pscustomobject]@{ command = ''; args = @(); url = '' } }
            continue
        }
        if ($srv -and $l -match '^command\s*=\s*["'']([^"'']*)["'']') { $servers[$srv].command = $Matches[1] }
        elseif ($srv -and $l -match '^args\s*=\s*\[(.*)\]') { $servers[$srv].args = @([regex]::Matches($Matches[1], '"((?:[^"\\]|\\.)*)"|''([^'']*)''') | ForEach-Object { $_.Groups[1].Value + $_.Groups[2].Value }) }
        elseif ($srv -and $l -match '^url\s*=\s*["'']([^"'']*)["'']') { $servers[$srv].url = $Matches[1] }
        elseif (-not $section -and $l -match '^approval_policy\s*=\s*"(never)"') { Add-Finding 'Medium' 'OpenAI Codex' $h.User 'Codex configured to never ask for approval' $l $h.Path }
        elseif (-not $section -and $l -match '^sandbox_mode\s*=\s*"(danger-full-access)"') { Add-Finding 'Medium' 'OpenAI Codex' $h.User 'Codex sandbox disabled (danger-full-access)' $l $h.Path }
        elseif (-not $section -and $l -match '^notify\s*=\s*(.+)$') {
            $notify = $Matches[1]
            $nsev = if ($notify -match $RxCradle) { 'High' } else { 'Low' }
            $HookRows.Add([pscustomobject]@{ Agent = 'OpenAI Codex'; User = $h.User; Event = 'notify'; Command = (Trunc $notify 500); Severity = $nsev; Flags = ''; Source = $h.Path })
            Add-Finding $nsev 'OpenAI Codex' $h.User 'Codex notify program configured' $notify $h.Path
        }
    }
    foreach ($k in $servers.Keys) { Add-McpServer 'OpenAI Codex' $h.User $h.Path 'config.toml' $k $servers[$k] }
}

# MCP servers removed since an older copy of ~/.claude.json
$current = @{}
foreach ($r in $McpRows) { if ($r.Source -like '*\.claude.json') { $current[$r.User + '|' + $r.Server] = 1 } }
foreach ($h in Get-Kind 'claude-global-backup') {
    $obj = ConvertFrom-JsonLoose (Read-SharedText $h.Path)
    if (-not $obj) { continue }
    $acc = New-Object System.Collections.Generic.List[object]
    Find-McpServers $obj '' 0 $false $acc
    foreach ($a in $acc) {
        if (-not $current.ContainsKey($h.User + '|' + $a[1])) {
            $current[$h.User + '|' + $a[1]] = 1
            $cmd = [string](Get-Prop $a[2] 'command'); $url = [string](Get-Prop $a[2] 'url')
            Add-Finding 'Medium' 'Claude Code' $h.User ("MCP server '{0}' was removed (still in a .claude.json backup)" -f $a[1]) ("{0} {1} {2}" -f $cmd, ((Get-Prop $a[2] 'args') -join ' '), $url) $h.Path
        }
    }
}

# Settings: hooks + approval posture
$claudeRetention = @{}
foreach ($h in @(Get-Kind 'claude-settings') + @(Get-Kind 'hooks-json') + @(Get-Kind 'cursor-settings')) {
    $text = Read-SharedText $h.Path
    $obj = ConvertFrom-JsonLoose $text
    if (-not $obj) { continue }
    $hooks = Get-Prop $obj 'hooks'
    if ($hooks) { Add-Hooks $h.Agent $h.User $h.Path $hooks }
    if ($h.Kind -eq 'claude-settings') {
        $perm = Get-Prop $obj 'permissions'
        $mode = [string](Get-Prop $perm 'defaultMode')
        if ($mode -eq 'bypassPermissions') { Add-Finding 'Medium' 'Claude Code' $h.User 'Claude Code defaults to bypassPermissions' 'permissions.defaultMode = bypassPermissions' $h.Path }
        if ((Get-Prop $obj 'skipDangerousModePermissionPrompt') -eq $true) { Add-Finding 'Low' 'Claude Code' $h.User 'Bypass-mode warning was accepted and silenced' 'skipDangerousModePermissionPrompt = true' $h.Path }
        foreach ($rule in @(Get-Prop $perm 'allow')) {
            if ([string]$rule -match '^(Bash|PowerShell)(\(\*\)|\(\*:\*\))?$|^\*$') { Add-Finding 'Medium' 'Claude Code' $h.User 'Blanket shell permission rule' ("allow: {0}" -f $rule) $h.Path }
        }
        $days = Get-Prop $obj 'cleanupPeriodDays'
        if ($null -ne $days) {
            $claudeRetention[$h.User] = [int]$days
            if ([int]$days -lt 7) { Add-Finding 'Medium' 'Claude Code' $h.User 'Transcript retention shortened' ("cleanupPeriodDays = {0} (default 30)" -f $days) $h.Path }
        }
    }
    if ($h.Kind -eq 'cursor-settings' -and $text -match '(?i)"[^"]*(yolo|autorun|auto-run)[^"]*"\s*:\s*true|"Shell\(\*\)"') {
        Add-Finding 'Medium' 'Cursor' $h.User 'Cursor auto-runs agent commands' $Matches[0] $h.Path
    }
}
foreach ($h in Get-Kind 'hook-script') {
    $HookRows.Add([pscustomobject]@{ Agent = $h.Agent; User = $h.User; Event = 'script'; Command = $h.Path; Severity = 'Low'; Flags = ''; Source = $h.Path })
}
foreach ($h in Get-Kind 'copilot-perms') {
    $obj = ConvertFrom-JsonLoose (Read-SharedText $h.Path)
    $locs = Get-Prop $obj 'locations'
    if ($locs) { Add-Finding 'Info' $h.Agent $h.User 'Copilot CLI saved approvals' ('{0} project locations with saved tool approvals' -f @($locs.PSObject.Properties).Count) $h.Path }
}

# Hidden Unicode in instruction files and MCP configs
foreach ($h in @(Get-Kind 'instructions') + @(Get-Kind 'mcp-json') + @(Get-Kind 'cursor-mcpcache')) {
    if ($h.Path -notmatch $TextExt -or $h.Info.Length -gt 5MB) { continue }
    $text = Read-SharedText $h.Path
    $hid = Get-HiddenUnicode $text
    if ($hid) {
        $sev = if ($hid.Severe) { 'High' } else { 'Medium' }
        $d = '{0} hidden characters ({1})' -f $hid.Count, $hid.Kinds
        if ($hid.Decoded) { $d += (" | decoded tag text: '{0}'" -f $hid.Decoded) }
        Add-Finding $sev $h.Agent $h.User 'Hidden Unicode in an agent instruction/config file' $d $h.Path
    }
    if ($h.Kind -eq 'cursor-mcpcache' -and $text) {
        $m = [regex]::Match($text, $RxInject)
        if ($m.Success) { Add-Finding 'High' 'Cursor' $h.User 'Cached MCP tool metadata contains an injection marker' ("'{0}' | {1}" -f $m.Value, $text) $h.Path }
    }
}

if ($Deep) {
    # Claude Code transcripts: tool calls, prompts, hook runs, tool descriptions, permission mode
    $claudeSessions = @{}
    $bypassBy = @{}
    foreach ($h in Get-Kind 'claude-transcript') {
        if ($h.Path -notlike '*.jsonl') { continue }
        $sid = [IO.Path]::GetFileNameWithoutExtension($h.Path)
        if ($h.Path -notmatch '\\subagents\\') { $claudeSessions[$h.User + '|' + $sid] = 1 }
        $bypass = 0
        $fs = $null
        try {
            $fs = Open-Shared $h.Path
            $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
            while ($null -ne ($line = $sr.ReadLine())) {
                if ($line.Contains('"permissionMode":"bypassPermissions"')) { $bypass++ }
                if ($line.StartsWith('{"type":"api-request-shape"') -or $line.Contains('"type":"api-request-shape"')) {
                    $r = $null; try { $r = $line | ConvertFrom-Json } catch { }
                    foreach ($t in @(Get-Prop (Get-Prop $r 'shape') 'tools')) {
                        $tn = [string](Get-Prop $t 'name')
                        if ($tn -like 'mcp__*') { Test-ToolDescription 'Claude Code' $h.User $tn ([string](Get-Prop $t 'description')) ([string](Get-Prop $r 'timestamp')) $sid $h.Path }
                    }
                    continue
                }
                if ($line.Contains('"type":"assistant"') -and $line.Contains('"tool_use"')) {
                    $r = $null; try { $r = $line | ConvertFrom-Json } catch { continue }
                    foreach ($c in @(Get-Prop (Get-Prop $r 'message') 'content')) {
                        if ((Get-Prop $c 'type') -ne 'tool_use') { continue }
                        $in = Get-Prop $c 'input'
                        $detail = $null
                        foreach ($k in @('command', 'file_path', 'path', 'url', 'pattern', 'query', 'prompt')) { $v = Get-Prop $in $k; if ($v) { $detail = [string]$v; break } }
                        if (-not $detail -and $in) { $detail = ($in | ConvertTo-Json -Compress -Depth 4) }
                        $actor = if ((Get-Prop $r 'isSidechain') -eq $true) { 'subagent' } else { 'agent' }
                        Add-Activity (Get-Prop $r 'timestamp') 'Claude Code' $h.User $sid $actor ([string](Get-Prop $c 'name')) $detail ([string](Get-Prop $r 'cwd')) $h.Path
                    }
                    continue
                }
                if ($line.Contains('"type":"user"') -and -not $line.Contains('"tool_result"') -and $line.Contains('"userType":"external"')) {
                    $r = $null; try { $r = $line | ConvertFrom-Json } catch { continue }
                    $content = Get-Prop (Get-Prop $r 'message') 'content'
                    if ($content -is [string] -and $content -and -not $content.StartsWith('<')) {
                        Add-Activity (Get-Prop $r 'timestamp') 'Claude Code' $h.User $sid 'user' 'PROMPT' $content ([string](Get-Prop $r 'cwd')) $h.Path
                    }
                    continue
                }
                if ($line.Contains('"hookInfos"')) {
                    $r = $null; try { $r = $line | ConvertFrom-Json } catch { continue }
                    foreach ($hi in @(Get-Prop $r 'hookInfos')) {
                        Add-Activity (Get-Prop $r 'timestamp') 'Claude Code' $h.User $sid 'hook' 'HOOK' ([string](Get-Prop $hi 'command')) ([string](Get-Prop $r 'cwd')) $h.Path
                    }
                }
            }
        } catch { } finally { if ($fs) { $fs.Dispose() } }
        if ($bypass -gt 0) {
            if (-not $bypassBy.ContainsKey($h.User)) { $bypassBy[$h.User] = New-Object System.Collections.Generic.List[string] }
            $bypassBy[$h.User].Add($sid)
        }
    }
    foreach ($u in $bypassBy.Keys) {
        $ids = $bypassBy[$u]
        Add-Finding 'Medium' 'Claude Code' $u 'Sessions ran with all permission checks bypassed' ('{0} sessions recorded permissionMode=bypassPermissions, e.g. {1}' -f $ids.Count, (($ids | Select-Object -First 3) -join ', ')) ''
    }

    # Claude Code prompt history vs transcripts: what was deleted?
    foreach ($h in Get-Kind 'claude-history') {
        $last = @{}; $proj = @{}
        $fs = $null
        try {
            $fs = Open-Shared $h.Path
            $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
            while ($null -ne ($line = $sr.ReadLine())) {
                $r = $null; try { $r = $line | ConvertFrom-Json } catch { continue }
                $sid = [string](Get-Prop $r 'sessionId'); $ts = Get-Prop $r 'timestamp'
                $when = ''
                if ($ts -is [long] -or $ts -is [int] -or $ts -is [double]) { $when = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$ts).UtcDateTime.ToString('o') } else { $when = [string]$ts }
                Add-Activity $when 'Claude Code' $h.User $sid 'user' 'PROMPT (history)' ([string](Get-Prop $r 'display')) ([string](Get-Prop $r 'project')) $h.Path
                if ($sid) { if (-not $last.ContainsKey($sid) -or $when -gt $last[$sid]) { $last[$sid] = $when; $proj[$sid] = [string](Get-Prop $r 'project') } }
            }
        } catch { } finally { if ($fs) { $fs.Dispose() } }
        $days = if ($claudeRetention.ContainsKey($h.User)) { $claudeRetention[$h.User] } else { 30 }
        $aged = 0
        foreach ($sid in $last.Keys) {
            if ($claudeSessions.ContainsKey($h.User + '|' + $sid)) { continue }
            $age = 0; try { $age = ($StartUtc - [DateTime]::Parse($last[$sid]).ToUniversalTime()).TotalDays } catch { }
            if ($age -gt ($days + 1)) { $aged++ }
            else { Add-Finding 'High' 'Claude Code' $h.User 'Transcript missing for a recent session' ('session {0} last prompt {1} in {2}: history.jsonl has it, projects\ does not (deleted or purged; retention is {3} days)' -f $sid, $last[$sid], $proj[$sid], $days) $h.Path }
        }
        if ($aged -gt 0) { Add-Finding 'Info' 'Claude Code' $h.User 'Sessions aged out by the retention sweep' ('{0} sessions in history.jsonl are older than {1} days and have no transcript (expected behaviour)' -f $aged, $days) $h.Path }
    }
    foreach ($h in Get-Kind 'claude-lastcleanup') {
        Add-Finding 'Info' 'Claude Code' $h.User 'Retention sweep last ran' ((Read-SharedText $h.Path) + ' - every launch can delete transcripts older than cleanupPeriodDays') $h.Path
    }

    # Codex rollouts
    $codexIds = @{}
    $codexOpen = @{}
    foreach ($h in Get-Kind 'codex-rollout') {
        $sid = [IO.Path]::GetFileNameWithoutExtension($h.Path) -replace '^rollout-[0-9T:\-]+-', ''
        $codexIds[$h.User + '|' + $sid] = 1
        $never = 0; $full = 0
        $fs = $null
        try {
            $fs = Open-Shared $h.Path
            $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
            while ($null -ne ($line = $sr.ReadLine())) {
                if ($line.Contains('"type":"turn_context"')) {
                    if ($line.Contains('"approval_policy":"never"')) { $never++ }
                    if ($line.Contains('"danger-full-access"')) { $full++ }
                    continue
                }
                if (-not ($line.Contains('"exec_command_end"') -or $line.Contains('"patch_apply_end"') -or $line.Contains('"user_message"') -or $line.Contains('"mcp_tool_call_end"') -or $line.Contains('"session_meta"'))) { continue }
                $r = $null; try { $r = $line | ConvertFrom-Json } catch { continue }
                $p = Get-Prop $r 'payload'; $pt = [string](Get-Prop $p 'type'); $ts = [string](Get-Prop $r 'timestamp')
                switch ($pt) {
                    'exec_command_end' {
                        $cmd = @(Get-Prop $p 'command')
                        $text = if ($cmd.Count -ge 3 -and $cmd[1] -match '^(-Command|-c|-lc)$') { $cmd[-1] } else { $cmd -join ' ' }
                        Add-Activity $ts 'OpenAI Codex' $h.User $sid 'agent' ('shell (exit {0})' -f (Get-Prop $p 'exit_code')) $text ([string](Get-Prop $p 'cwd')) $h.Path
                    }
                    'patch_apply_end' {
                        $ch = Get-Prop $p 'changes'
                        $names = if ($ch) { ($ch.PSObject.Properties | ForEach-Object { $_.Name }) -join ', ' } else { '' }
                        Add-Activity $ts 'OpenAI Codex' $h.User $sid 'agent' 'apply_patch' $names '' $h.Path
                    }
                    'user_message' { Add-Activity $ts 'OpenAI Codex' $h.User $sid 'user' 'PROMPT' ([string](Get-Prop $p 'message')) '' $h.Path }
                    'mcp_tool_call_end' {
                        $inv = Get-Prop $p 'invocation'
                        Add-Activity $ts 'OpenAI Codex' $h.User $sid 'agent' ('mcp:{0}/{1}' -f (Get-Prop $inv 'server'), (Get-Prop $inv 'tool')) ((Get-Prop $inv 'arguments') | ConvertTo-Json -Compress -Depth 4) '' $h.Path
                    }
                    default {
                        if ([string](Get-Prop $r 'type') -eq 'session_meta') {
                            foreach ($t in @(Get-Prop $p 'dynamic_tools')) { Test-ToolDescription 'OpenAI Codex' $h.User ([string](Get-Prop $t 'name')) ([string](Get-Prop $t 'description')) $ts $sid $h.Path }
                        }
                    }
                }
            }
        } catch { } finally { if ($fs) { $fs.Dispose() } }
        if ($never -gt 0 -or $full -gt 0) {
            if (-not $codexOpen.ContainsKey($h.User)) { $codexOpen[$h.User] = New-Object System.Collections.Generic.List[string] }
            $codexOpen[$h.User].Add(('{0} ({1} never / {2} full-access turns)' -f $sid, $never, $full))
        }
    }
    foreach ($u in $codexOpen.Keys) {
        Add-Finding 'Medium' 'OpenAI Codex' $u 'Codex sessions ran without approvals or sandbox' ('{0} sessions, e.g. {1}' -f $codexOpen[$u].Count, (($codexOpen[$u] | Select-Object -First 3) -join '; ')) ''
    }
    foreach ($h in Get-Kind 'codex-index') {
        $fs = $null
        try {
            $fs = Open-Shared $h.Path
            $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
            while ($null -ne ($line = $sr.ReadLine())) {
                $r = $null; try { $r = $line | ConvertFrom-Json } catch { continue }
                $id = [string](Get-Prop $r 'id')
                if ($id -and -not $codexIds.ContainsKey($h.User + '|' + $id)) {
                    Add-Finding 'Medium' 'OpenAI Codex' $h.User 'Codex thread has no rollout file' ("thread {0} '{1}' updated {2}: indexed but its transcript is gone" -f $id, (Get-Prop $r 'thread_name'), (Get-Prop $r 'updated_at')) $h.Path
                }
            }
        } catch { } finally { if ($fs) { $fs.Dispose() } }
    }

    # Cursor agent transcripts (no per-record timestamps; use state.vscdb for time)
    foreach ($h in Get-Kind 'cursor-transcript') {
        if ($h.Path -notlike '*.jsonl') { continue }
        $sid = [IO.Path]::GetFileNameWithoutExtension($h.Path)
        $fs = $null
        try {
            $fs = Open-Shared $h.Path
            $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
            $i = 0
            while ($null -ne ($line = $sr.ReadLine())) {
                $i++
                $r = $null; try { $r = $line | ConvertFrom-Json } catch { continue }
                $role = [string](Get-Prop $r 'role')
                foreach ($c in @(Get-Prop (Get-Prop $r 'message') 'content')) {
                    $ct = [string](Get-Prop $c 'type')
                    if ($ct -eq 'tool_use') {
                        $in = Get-Prop $c 'input'; $detail = $null
                        foreach ($k in @('command', 'path', 'glob_pattern', 'pattern', 'search_term', 'url')) { $v = Get-Prop $in $k; if ($v) { $detail = [string]$v; break } }
                        Add-Activity ('(line {0}; file mtime {1})' -f $i, $h.Info.LastWriteTimeUtc.ToString('o')) 'Cursor' $h.User $sid 'agent' ([string](Get-Prop $c 'name')) $detail ([string](Get-Prop $in 'working_directory')) $h.Path
                    } elseif ($role -eq 'user' -and $ct -eq 'text') {
                        Add-Activity ('(line {0}; file mtime {1})' -f $i, $h.Info.LastWriteTimeUtc.ToString('o')) 'Cursor' $h.User $sid 'user' 'PROMPT' ([string](Get-Prop $c 'text')) '' $h.Path
                    }
                }
            }
        } catch { } finally { if ($fs) { $fs.Dispose() } }
    }

    # Copilot CLI / Gemini CLI events: schema varies by version, so read generically
    foreach ($h in @(Get-Kind 'copilot-events') + @(Get-Kind 'gemini-chat')) {
        if ($h.Path -notmatch '\.jsonl?$' -or $h.Info.Length -gt 268435456) { continue }
        $fs = $null
        try {
            $fs = Open-Shared $h.Path
            $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
            while ($null -ne ($line = $sr.ReadLine())) {
                if (-not ($line.Contains('"command"') -or $line.Contains('"toolName"'))) { continue }
                $r = $null; try { $r = $line | ConvertFrom-Json } catch { continue }
                $m = [regex]::Match($line, '"command"\s*:\s*"((?:[^"\\]|\\.){1,400})')
                $tm = [regex]::Match($line, '"(timestamp|time|createdAt)"\s*:\s*"([^"]+)"')
                $tn = [regex]::Match($line, '"(toolName|name)"\s*:\s*"([^"]+)"')
                Add-Activity ($(if ($tm.Success) { $tm.Groups[2].Value } else { '' })) $h.Agent $h.User ([IO.Path]::GetFileName((Split-Path $h.Path -Parent))) 'agent' ($(if ($tn.Success) { $tn.Groups[2].Value } else { 'tool' })) ($(if ($m.Success) { [regex]::Unescape($m.Groups[1].Value) } else { '' })) '' $h.Path
            }
        } catch { } finally { if ($fs) { $fs.Dispose() } }
    }
}

# MCP tool descriptions that changed between sessions (rug pull)
$ToolRows = New-Object System.Collections.Generic.List[object]
foreach ($e in $ToolsSeen.Values) {
    foreach ($k in $e.Hashes.Keys) {
        $v = $e.Hashes[$k]
        $ToolRows.Add([pscustomobject]@{
                Agent = $e.Agent; User = $e.User; Tool = $e.Tool; Version = $k; Versions = $e.Hashes.Count; VersionFirstSeenUtc = $v.Ts
                ToolFirstSeenUtc = $e.First; ToolLastSeenUtc = $e.Last; Flags = $v.Flags; Session = $v.Session; Description = (Trunc $v.Desc 2000); Source = $v.Source
            })
    }
    if ($e.Hashes.Count -gt 1) {
        $when = ($e.Hashes.Values | ForEach-Object { $_.Ts } | Sort-Object) -join ' -> '
        Add-Finding 'Low' $e.Agent $e.User ("MCP tool description changed between sessions: {0}" -f $e.Tool) ('{0} versions first seen at {1}; diff them in mcp_tools_seen.csv (a silent change is how a rug pull looks)' -f $e.Hashes.Count, $when) ''
    }
}

# Agents present per profile
$present = $Hits | Group-Object Agent | Sort-Object Count -Descending
#endregion

#region output --------------------------------------------------------------------------------
$sorted = @($Findings | Sort-Object @{ Expression = { $SevRank[$_.Severity] } }, Agent, Finding)
$counts = [ordered]@{ High = 0; Medium = 0; Low = 0; Info = 0 }
foreach ($f in $sorted) { $counts[$f.Severity]++ }

if ($Mode -eq 'Kansa') { $sorted; return }

if ($Mode -eq 'Intune') {
    $agents = [ordered]@{}
    foreach ($g in $present) { if ($g.Name -ne 'Project files') { $agents[$g.Name] = @($g.Group | Select-Object -ExpandProperty User -Unique).Count } }
    $top = @($sorted | Where-Object { $_.Severity -in @('High', 'Medium') } | Select-Object -First 6 | ForEach-Object { '{0}: {1} [{2}]' -f $_.Severity, (Trunc $_.Finding 70), $_.User })
    $out = [ordered]@{ host = $env:COMPUTERNAME; utc = $StartUtc.ToString('s') + 'Z'; agents = $agents; mcpServers = $McpRows.Count; hooks = $HookRows.Count; findings = $counts; top = $top }
    $json = $out | ConvertTo-Json -Compress -Depth 4
    if ($json.Length -gt 2000) { $out.top = @($top | Select-Object -First 2); $json = $out | ConvertTo-Json -Compress -Depth 4 }
    Write-Output $json
    if ($counts.High + $counts.Medium -gt 0) { exit 1 } else { exit 0 }
}

$files = [ordered]@{
    'findings.csv'       = $sorted
    'agent_activity.csv' = @($Activity.ToArray() | Sort-Object TimestampUtc)
    'mcp_servers.csv'    = $McpRows.ToArray()
    'hooks.csv'          = $HookRows.ToArray()
    'mcp_tools_seen.csv' = $ToolRows.ToArray()
    'manifest.csv'       = $Manifest.ToArray()
}
foreach ($k in $files.Keys) {
    $rows = $files[$k]
    if ($rows.Count -gt 0) { $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $repDir $k) }
}
$summary = [ordered]@{
    kit = 'Agent Triage Kit ' + $KitVersion; host = $env:COMPUTERNAME; mode = $Mode; elevated = $isAdmin; startedUtc = $StartUtc.ToString('o'); finishedUtc = [DateTime]::UtcNow.ToString('o')
    profiles = @($profiles); agents = [ordered]@{}; files = $Hits.Count; mcpServers = $McpRows.Count; hooks = $HookRows.Count; activityRows = $Activity.Count; findings = $counts
}
foreach ($g in $present) { $summary.agents[$g.Name] = $g.Count }
$summary | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $repDir 'summary.json')

if ($zip) {
    foreach ($f in Get-ChildItem -LiteralPath $repDir -File) {
        $e = $zip.CreateEntry('report/' + $f.Name)
        $w = $e.Open(); $r = [IO.File]::OpenRead($f.FullName); $r.CopyTo($w); $r.Dispose(); $w.Dispose()
    }
    $zip.Dispose(); $zipStream.Dispose()
}

Say ''
Say '  Agents found' 'Cyan'
foreach ($g in $present) { Say ('    {0,-22} {1,6} files  {2}' -f $g.Name, $g.Count, ((@($g.Group | Select-Object -ExpandProperty User -Unique)) -join ', ')) 'Gray' }
Say ''
Say ('  Findings   High {0}   Medium {1}   Low {2}   Info {3}' -f $counts.High, $counts.Medium, $counts.Low, $counts.Info) 'Cyan'
$colors = @{ High = 'Red'; Medium = 'Yellow'; Low = 'Gray'; Info = 'DarkGray' }
foreach ($f in ($sorted | Where-Object { $_.Severity -ne 'Info' } | Select-Object -First 15)) {
    Say ('    [{0,-6}] {1,-14} {2}' -f $f.Severity, $f.Agent, (Trunc $f.Finding 90)) $colors[$f.Severity]
}
Say ''
Say ('  MCP servers {0}  |  hooks {1}  |  activity rows {2}' -f $McpRows.Count, $HookRows.Count, $Activity.Count) 'Gray'
Say ('  Report  {0}' -f $repDir) 'Green'
if ($zipPath) { Say ('  ZIP     {0}' -f $zipPath) 'Green'; Say ('  SHA256  {0}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash) 'Green' }
Say ''
#endregion

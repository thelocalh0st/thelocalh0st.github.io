#!/usr/bin/env bash
# Agent Triage Kit: collect and triage AI coding agent artifacts on macOS and Linux.
#
# Collects transcripts, configuration, MCP server definitions, hooks and logs left by
# AI coding agents into one tar.gz with a SHA256 manifest, then runs the bundled
# analyzer (python3) for findings and an activity timeline.
# Read-only on the source. Do not open the agents on a suspect host first: Claude Code
# runs its retention sweep at startup and deletes transcripts older than cleanupPeriodDays.
#
# Generated 2026-10-31 by the Agent Triage Kit for: Claude Code, OpenAI Codex, Cursor, GitHub Copilot CLI, VS Code Copilot Chat, Gemini CLI, Antigravity, Windsurf, Cline.
# Agent Triage Kit by Sujay Adkesar - https://thelocalh0st.com   License: MIT
#
# usage: sudo bash agent_triage.sh [-o OUTDIR] [--home DIR]... [--include-secrets]
#                                  [--max-mb N] [--depth N] [--no-projects] [--no-analyze]

set -u
OUT="/tmp/agent_triage"; HOMES=(); INCLUDE_SECRETS=0; MAXMB=1024; DEPTH=6; ANALYZE=1
PROJECT_SWEEP=1
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out) OUT="$2"; shift 2 ;;
    --home) HOMES+=("$2"); shift 2 ;;
    --include-secrets) INCLUDE_SECRETS=1; shift ;;
    --max-mb) MAXMB="$2"; shift 2 ;;
    --depth) DEPTH="$2"; shift 2 ;;
    --no-projects) PROJECT_SWEEP=0; shift ;;
    --no-analyze) ANALYZE=0; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$(uname -s)" in
  Darwin) OS=mac; APPSUP="Library/Application Support" ;;
  *) OS=linux; APPSUP=".config" ;;
esac
shopt -s nullglob dotglob
TAB="$(printf '\t')"

if [ ${#HOMES[@]} -eq 0 ]; then
  if [ "$(id -u)" -eq 0 ]; then
    for h in /Users/* /home/* /root; do
      [ -d "$h" ] || continue
      case "$h" in /Users/Shared|/Users/Guest) continue ;; esac
      HOMES+=("$h")
    done
  else
    HOMES=("$HOME")
  fi
fi

HOST="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CASE="AgentTriage_${HOST}_${STAMP}"
CASEDIR="$OUT/$CASE"
mkdir -p "$CASEDIR/report" || exit 1
META="$CASEDIR/.meta"; LIST="$CASEDIR/.files"
: > "$META"

# os|agent|category|kind|base|path|mask|recurse|secret
TARGETS='any|Claude Code|Transcripts|claude-transcript|home|.claude/projects|*|1|0
any|Claude Code|Prompt history|claude-history|home|.claude|history.jsonl|0|0
any|Claude Code|File snapshots|-|home|.claude/file-history|*|1|0
any|Claude Code|Settings|claude-settings|home|.claude|settings.json|0|0
any|Claude Code|Settings|claude-settings|home|.claude|settings.local.json|0|0
any|Claude Code|Global state + MCP|claude-global|home|-|.claude.json|0|0
any|Claude Code|Global state + MCP|claude-global-backup|home|.claude/backups|*|0|0
any|Claude Code|Instructions|instructions|home|.claude|CLAUDE.md|0|0
any|Claude Code|Instructions|instructions|home|.claude/agents|*|1|0
any|Claude Code|Instructions|instructions|home|.claude/skills|*.md|1|0
any|Claude Code|Instructions|instructions|home|.claude/commands|*|1|0
any|Claude Code|Instructions|instructions|home|.claude/rules|*|1|0
any|Claude Code|Session state|-|home|.claude/shell-snapshots|*|1|0
any|Claude Code|Session state|-|home|.claude/session-env|*|1|0
any|Claude Code|Session state|-|home|.claude/plans|*|1|0
any|Claude Code|Session state|-|home|.claude/tasks|*|1|0
any|Claude Code|Session state|-|home|.claude/todos|*|1|0
any|Claude Code|Session state|claude-lastcleanup|home|.claude|.last-cleanup|0|0
any|Claude Code|Logs|-|home|.claude/debug|*|1|0
any|Claude Code|Plugins|-|home|.claude/plugins|*.json|0|0
any|Claude Code|Credentials|-|home|.claude|.credentials.json|0|1
any|Claude Code|Desktop MCP config|mcp-json|appdata|Claude|claude_desktop_config.json|0|0
mac|Claude Code|Desktop MCP logs|-|maclogs|Claude|mcp*.log|0|0
mac|Claude Code|Managed policy|claude-settings|system|/Library/Application Support/ClaudeCode|managed-settings.json|0|0
mac|Claude Code|Managed policy|mcp-json|system|/Library/Application Support/ClaudeCode|managed-mcp.json|0|0
any|OpenAI Codex|Transcripts|codex-rollout|home|.codex/sessions|*.jsonl|1|0
any|OpenAI Codex|Transcripts|codex-rollout|home|.codex/archived_sessions|*.jsonl|1|0
any|OpenAI Codex|Session index|codex-index|home|.codex|session_index.jsonl|0|0
any|OpenAI Codex|Prompt history|-|home|.codex|history.jsonl|0|0
any|OpenAI Codex|State + logs DB|-|home|.codex|state_*.sqlite*|0|0
any|OpenAI Codex|State + logs DB|-|home|.codex|logs_*.sqlite*|0|0
any|OpenAI Codex|Config + MCP|codex-config|home|.codex|config.toml|0|0
any|OpenAI Codex|Instructions|instructions|home|.codex|AGENTS.md|0|0
any|OpenAI Codex|Instructions|instructions|home|.codex/rules|*|1|0
any|OpenAI Codex|Instructions|-|home|.codex/memories|*|1|0
any|OpenAI Codex|Logs|-|home|.codex/log|*|1|0
any|OpenAI Codex|Credentials|-|home|.codex|auth.json|0|1
any|Cursor|Transcripts|cursor-transcript|home|.cursor/projects/*/agent-transcripts|*|1|0
any|Cursor|Agent tool output|-|home|.cursor/projects/*/agent-tools|*|1|0
any|Cursor|Agent tool output|-|home|.cursor/projects/*/terminals|*|1|0
any|Cursor|MCP tool cache|cursor-mcpcache|home|.cursor/projects/*/mcps|*|1|0
any|Cursor|Config + MCP|mcp-json|home|.cursor|mcp.json|0|0
any|Cursor|Hooks|hooks-json|home|.cursor|hooks.json|0|0
any|Cursor|Hooks|-|home|.cursor/hooks|*|1|0
any|Cursor|Config + MCP|cursor-settings|home|.cursor|cli-config.json|0|0
any|Cursor|Instructions|instructions|home|.cursor/rules|*|1|0
any|Cursor|AI code tracking|-|home|.cursor/ai-tracking|*|1|0
any|Cursor|CLI chats|-|home|.cursor/chats|*|1|0
any|Cursor|State DB|-|appdata|Cursor/User/globalStorage|state.vscdb*|0|0
any|Cursor|State DB|-|appdata|Cursor/User/workspaceStorage/*|state.vscdb*|0|0
any|Cursor|State DB|-|appdata|Cursor/User/workspaceStorage/*|workspace.json|0|0
any|Cursor|Config + MCP|cursor-settings|appdata|Cursor/User|settings.json|0|0
any|Cursor|Config + MCP|mcp-json|appdata|Cursor/User|mcp.json|0|0
any|Cursor|Logs|-|appdata|Cursor/logs|*|1|0
any|GitHub Copilot CLI|Transcripts|copilot-events|home|.copilot/session-state|*|1|0
any|GitHub Copilot CLI|Transcripts|copilot-events|home|.copilot/history-session-state|*|1|0
any|GitHub Copilot CLI|Session index|-|home|.copilot|session-store.db*|0|0
any|GitHub Copilot CLI|Prompt history|-|home|.copilot/command-history-state|*|1|0
any|GitHub Copilot CLI|Config + MCP|mcp-json|home|.copilot|mcp-config.json|0|0
any|GitHub Copilot CLI|Config + MCP|-|home|.copilot|config.json|0|0
any|GitHub Copilot CLI|Config + MCP|hooks-json|home|.copilot|settings.json|0|0
any|GitHub Copilot CLI|Saved approvals|copilot-perms|home|.copilot|permissions-config.json|0|0
any|GitHub Copilot CLI|Hooks|hook-script|home|.copilot/hooks|*|1|0
any|GitHub Copilot CLI|Instructions|instructions|home|.copilot|copilot-instructions.md|0|0
any|GitHub Copilot CLI|Instructions|instructions|home|.copilot/agents|*|1|0
any|GitHub Copilot CLI|Instructions|instructions|home|.copilot/instructions|*|1|0
any|GitHub Copilot CLI|Logs|-|home|.copilot/logs|*|1|0
any|GitHub Copilot CLI|Credentials|-|home|.copilot/mcp-oauth-config|*|1|1
any|VS Code Copilot Chat|Transcripts|-|appdata|Code/User/workspaceStorage/*/chatSessions|*|1|0
any|VS Code Copilot Chat|Transcripts|-|appdata|Code/User/workspaceStorage/*/chatEditingSessions|*|1|0
any|VS Code Copilot Chat|Transcripts|-|appdata|Code/User/globalStorage/emptyWindowChatSessions|*|1|0
any|VS Code Copilot Chat|State DB|-|appdata|Code/User/workspaceStorage/*|workspace.json|0|0
any|VS Code Copilot Chat|Config + MCP|mcp-json|appdata|Code/User|mcp.json|0|0
any|VS Code Copilot Chat|Config + MCP|-|appdata|Code/User|settings.json|0|0
any|VS Code Copilot Chat|Logs|-|appdata|Code/logs|*|1|0
any|Gemini CLI|Transcripts|gemini-chat|home|.gemini/tmp|*|1|0
any|Gemini CLI|Config + MCP|gemini-settings|home|.gemini|settings.json|0|0
any|Gemini CLI|Instructions|instructions|home|.gemini|GEMINI.md|0|0
any|Gemini CLI|Instructions|instructions|home|.gemini/commands|*|1|0
any|Gemini CLI|Extensions|mcp-json|home|.gemini/extensions|gemini-extension.json|1|0
any|Gemini CLI|Credentials|-|home|.gemini|oauth_creds.json|0|1
any|Gemini CLI|Credentials|-|home|.gemini|google_accounts.json|0|1
any|Antigravity|Config + MCP|mcp-json|home|.gemini/antigravity|mcp_config.json|0|0
any|Antigravity|Transcripts|antigravity|home|.gemini/antigravity|*|1|0
any|Antigravity|State DB|-|appdata|Antigravity/User/globalStorage|state.vscdb*|0|0
any|Antigravity|State DB|-|appdata|Antigravity/User/workspaceStorage/*|state.vscdb*|0|0
any|Antigravity|State DB|-|appdata|Antigravity/User/workspaceStorage/*|workspace.json|0|0
any|Antigravity|Config + MCP|-|appdata|Antigravity/User|settings.json|0|0
any|Antigravity|Logs|-|appdata|Antigravity/logs|*|1|0
any|Windsurf|Config + MCP|mcp-json|home|.codeium/windsurf|mcp_config.json|0|0
any|Windsurf|Instructions|instructions|home|.codeium/windsurf/memories|*.md|0|0
any|Windsurf|Transcripts|windsurf|home|.codeium/windsurf|*|1|0
any|Windsurf|State DB|-|appdata|Windsurf/User/globalStorage|state.vscdb*|0|0
any|Windsurf|State DB|-|appdata|Windsurf/User/workspaceStorage/*|state.vscdb*|0|0
any|Windsurf|State DB|-|appdata|Windsurf/User/workspaceStorage/*|workspace.json|0|0
any|Windsurf|Config + MCP|-|appdata|Windsurf/User|settings.json|0|0
any|Windsurf|Logs|-|appdata|Windsurf/logs|*|1|0
any|Cline|Transcripts|-|appdata|Code/User/globalStorage/saoudrizwan.claude-dev/tasks|*|1|0
any|Cline|Config + MCP|mcp-json|appdata|Code/User/globalStorage/saoudrizwan.claude-dev/settings|*|1|0
any|Cline|Transcripts|-|appdata|Cursor/User/globalStorage/saoudrizwan.claude-dev/tasks|*|1|0
any|Cline|Config + MCP|mcp-json|appdata|Cursor/User/globalStorage/saoudrizwan.claude-dev/settings|*|1|0
any|Cline|Transcripts|-|home|.cline|*|1|0
linux|Claude Code|Desktop MCP logs|-|appdata|Claude/logs|mcp*.log|0|0
linux|Claude Code|Managed policy|claude-settings|system|/etc/claude-code|managed-settings.json|0|0
linux|Claude Code|Managed policy|mcp-json|system|/etc/claude-code|managed-mcp.json|0|0'
# name|ext|parents|kind
PROJECT_FILES='.mcp.json|-|-|mcp-json
mcp.json|-|.vscode,.cursor,.github|mcp-json
settings.json|-|.claude|claude-settings
settings.local.json|-|.claude|claude-settings
settings.json|-|.gemini|gemini-settings
hooks.json|-|.cursor|hooks-json
config.toml|-|.codex|codex-config
CLAUDE.md|-|-|instructions
CLAUDE.local.md|-|-|instructions
AGENTS.md|-|-|instructions
GEMINI.md|-|-|instructions
.cursorrules|-|-|instructions
.windsurfrules|-|-|instructions
.clinerules|-|-|instructions
copilot-instructions.md|-|-|instructions
SKILL.md|-|-|instructions
-|.mdc|rules|instructions
-|.instructions.md|-|instructions'

say() { printf '  %s\n' "$*"; }
say "Agent Triage Kit  |  AI coding agent forensics for macOS / Linux"
say "host $HOST  |  os $OS  |  uid $(id -u)  |  homes ${#HOMES[@]}"
[ "$(id -u)" -ne 0 ] && [ "${HOMES[0]}" = "$HOME" ] && say "Not root: only $HOME is covered."

emit() { # file agent category secret
  [ -f "$1" ] || return 0
  local c=yes
  if [ "$4" = 1 ] && [ "$INCLUDE_SECRETS" = 0 ]; then c="no (credential file)"; fi
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$c" >> "$META"
}

scan_dir() { # dir mask recurse agent category secret
  [ -d "$1" ] || return 0
  local depth=""
  [ "$3" = 1 ] || depth="-maxdepth 1"
  # shellcheck disable=SC2086
  while IFS= read -r -d '' f; do emit "$f" "$4" "$5" "$6"; done \
    < <(find "$1" $depth -type f -name "$2" -size -"${MAXMB}"M -print0 2>/dev/null)
}

expand_root() { # a root with at most one "*" segment -> the folders that exist
  local root="$1" prefix rest d
  case "$root" in
    *'*'*)
      prefix="${root%%\**}"; rest="${root#*\*}"; prefix="${prefix%/}"
      for d in "$prefix"/*; do [ -d "$d$rest" ] && printf '%s\n' "$d$rest"; done ;;
    *) [ -d "$root" ] && printf '%s\n' "$root" ;;
  esac
  return 0
}

while IFS='|' read -r tos agent cat kind base path mask rec sec; do
  [ -n "$tos" ] || continue
  [ "$tos" = any ] || [ "$tos" = "$OS" ] || continue
  [ "$path" = - ] && path=""
  if [ "$base" = system ]; then scan_dir "$path" "$mask" 0 "$agent" "$cat" "$sec"; continue; fi
  for h in "${HOMES[@]}"; do
    case "$base" in
      home) root="$h${path:+/$path}" ;;
      appdata) root="$h/$APPSUP${path:+/$path}" ;;
      maclogs) root="$h/Library/Logs${path:+/$path}" ;;
      *) continue ;;
    esac
    while IFS= read -r d; do scan_dir "$d" "$mask" "$rec" "$agent" "$cat" "$sec"; done < <(expand_root "$root")
  done
done <<< "$TARGETS"

project_kind() { # file -> 0 when it is a repo-level agent file
  local n p pn pe pp pk
  n="$(basename "$1" | tr '[:upper:]' '[:lower:]')"
  p="$(basename "$(dirname "$1")" | tr '[:upper:]' '[:lower:]')"
  while IFS='|' read -r pn pe pp pk; do
    if [ "$pp" != - ]; then case ",$pp," in *",$p,"*) ;; *) continue ;; esac; fi
    pn="$(printf '%s' "$pn" | tr '[:upper:]' '[:lower:]')"
    [ "$pn" != - ] && [ "$n" = "$pn" ] && return 0
    if [ "$pe" != - ]; then case "$n" in *"$pe") return 0 ;; esac; fi
  done <<< "$PROJECT_FILES"
  return 1
}

if [ "$PROJECT_SWEEP" = 1 ]; then
  for h in "${HOMES[@]}"; do
    while IFS= read -r -d '' f; do
      project_kind "$f" && emit "$f" "Project files" "Repository config" 0
    done < <(find "$h" -maxdepth "$DEPTH" \( -type d \( -name node_modules -o -name .git -o -name Library -o -name .cache \
        -o -name .venv -o -name venv -o -name .npm -o -name .cargo -o -name .rustup -o -name .Trash \
        -o -path '*/.claude/projects' -o -path '*/.cursor/projects' -o -path '*/.cursor/extensions' -o -path '*/.vscode/extensions' \
        -o -path '*/.codex/sessions' -o -path '*/.gemini/antigravity' -o -path '*/.gemini/tmp' -o -path '*/.codeium/windsurf' \) -prune \) \
        -o -type f \( -iname '.mcp.json' -o -iname 'mcp.json' -o -iname 'CLAUDE.md' -o -iname 'CLAUDE.local.md' -o -iname 'AGENTS.md' \
        -o -iname 'GEMINI.md' -o -iname '.cursorrules' -o -iname '.windsurfrules' -o -iname '.clinerules' -o -iname 'copilot-instructions.md' \
        -o -iname 'SKILL.md' -o -iname '*.mdc' -o -iname '*.instructions.md' -o -iname 'settings.json' -o -iname 'settings.local.json' \
        -o -iname 'hooks.json' -o -iname 'config.toml' \) -size -5M -print0 2>/dev/null)
  done
fi

# targets overlap with the project sweep: keep the first record per path
awk -F "$TAB" '!seen[$1]++' "$META" > "$META.u" && mv "$META.u" "$META"
awk -F "$TAB" '$4 == "yes" { print $1 }' "$META" | tr '\n' '\0' > "$LIST"
say "found $(wc -l < "$META" | tr -d ' ') artifact files"

# manifest: path, agent, category, size, mtime, birth time, sha256, collected
MAN="$CASEDIR/report/manifest.tsv"
printf 'Path\tAgent\tCategory\tSize\tModifiedUtc\tBirthUtc\tSHA256\tCollected\n' > "$MAN"
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
if stat -c %s / >/dev/null 2>&1; then STATF="-c %s_%Y_%W"; else STATF="-f %z_%m_%B"; fi
iso() {
  case "$1" in ''|0|-|'?') echo ""; return ;; esac
  date -u -d "@$1" +%FT%TZ 2>/dev/null || date -u -r "$1" +%FT%TZ 2>/dev/null
}
say "hashing ..."
while IFS="$TAB" read -r f agent cat collected; do
  # shellcheck disable=SC2086
  st="$(stat $STATF "$f" 2>/dev/null)"
  size="${st%%_*}"; rest="${st#*_}"; mt="${rest%%_*}"; bt="${rest#*_}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$agent" "$cat" "$size" "$(iso "$mt")" "$(iso "$bt")" \
    "$($SHA "$f" 2>/dev/null | cut -d' ' -f1)" "$collected" >> "$MAN"
done < "$META"

say "archiving ..."
ARCHIVE="$OUT/$CASE.tar.gz"
tar -cf - --null -T "$LIST" 2>/dev/null | gzip -6 > "$ARCHIVE"

if [ "$ANALYZE" = 1 ] && command -v python3 >/dev/null 2>&1 && python3 -c 'import sqlite3' >/dev/null 2>&1; then
  say "analyzing ..."
  PYF="$CASEDIR/.agent_triage_analyze.py"
  cat > "$PYF" <<'ATK_PY_EOF'
#!/usr/bin/env python3
"""Agent Triage Kit - offline analyzer for AI coding agent artifacts.

Reads the ZIP from AgentTriage.ps1, the tar.gz from agent_triage.sh, a KAPE or
Velociraptor collection folder, or the live machine (--live), and writes:

  findings.csv        what needs a look, ranked High / Medium / Low / Info
  agent_activity.csv  one timeline of agent tool calls, user prompts and hook runs
  mcp_servers.csv     every MCP server definition, with risk flags
  hooks.csv           agent hooks and notify programs
  mcp_tools_seen.csv  MCP tool descriptions the model actually saw, per version
  report.html         the same, in one page you can filter
  summary.json

On top of the PowerShell collector it reads Cursor's state.vscdb (per-call
timestamps, user-rejected commands), Cursor's AI code tracking DB (files the
agent deleted), Codex's thread index (rollouts that are gone) and VS Code chats.

Stdlib only, Python 3.8+.  Agent Triage Kit by Sujay Adkesar - https://thelocalh0st.com
License: MIT
"""
import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import os
import posixpath
import re
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import zipfile

SEV_RANK = {'High': 0, 'Medium': 1, 'Low': 2, 'Info': 3}

RX_CRADLE = re.compile(r'(\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-bitstransfer|'
                       r'\bcurl(\.exe)?\s|\bwget\s|certutil(\.exe)?\s.*urlcache|bitsadmin|frombase64string|'
                       r'\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{16,}|\|\s*(ba|z)?sh\b|\|\s*iex\b|invoke-expression|\bnc(at)?\s+-e)', re.I)
RX_SHELL = re.compile(r'(^|[\\/])(powershell|pwsh|cmd|bash|sh|zsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?$', re.I)
RX_INLINE = re.compile(r'^(-c|-command|/c|/k|-e|-enc|-encodedcommand|-lc)$', re.I)
RX_TEMP = re.compile(r'(\\temp\\|\\tmp\\|/tmp/|\\downloads\\|/downloads/|\\users\\public\\|\\programdata\\[^\\]+\.exe)', re.I)
RX_RUNNER = re.compile(r'(^|[\\/])(npx|bunx|uvx|pnpx)(\.cmd|\.exe)?$', re.I)
RX_SECRET = re.compile(r'(token|secret|passw|api[_-]?key|access[_-]?key|private[_-]?key|\bpat\b|auth)', re.I)
RX_INJECT = re.compile(r'(ignore (all |any )?(previous|prior|above) instructions|<\s*/?\s*(important|system|secret|instructions?)\s*>|'
                       r'before (using|calling|invoking) (this|any other|any) tool|[\\/]\.ssh[\\/]|id_rsa|\.aws[\\/]credentials|'
                       r'wallet\.dat|\bseed phrase|send (it|them|the (file|contents?|output)) to|exfiltrat)', re.I)
RX_INJECT_WEAK = re.compile(r"(do not|don't|never) (tell|inform|mention|reveal|narrate|show)[^.\n]{0,40}user", re.I)
HIDDEN = re.compile('[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\U000E0000-\U000E007F]')
TEXT_EXT = re.compile(r'\.(md|mdc|txt|json|jsonc|toml|ya?ml|rules|instructions)$|/\.(cursorrules|windsurfrules|clinerules)$', re.I)

# (path regex, agent, kind). First match wins; paths are normalised to forward slashes.
RULES = [
    (r'/\.claude/projects/[^/]+/.+\.jsonl$', 'Claude Code', 'claude-transcript'),
    (r'/\.claude/history\.jsonl$', 'Claude Code', 'claude-history'),
    (r'/\.claude/settings(\.local)?\.json$|/claude-?code/managed-settings\.json$', 'Claude Code', 'claude-settings'),
    (r'/\.claude\.json$', 'Claude Code', 'claude-global'),
    (r'/\.claude/backups/\.claude\.json\.backup', 'Claude Code', 'claude-global-backup'),
    (r'/\.claude/\.last-cleanup$', 'Claude Code', 'claude-lastcleanup'),
    (r'claude_desktop_config\.json$|/managed-mcp\.json$', 'Claude Code', 'mcp-json'),
    (r'/\.codex/(archived_)?sessions/.+\.jsonl$', 'OpenAI Codex', 'codex-rollout'),
    (r'/\.codex/session_index\.jsonl$', 'OpenAI Codex', 'codex-index'),
    (r'/\.codex/state_\d+\.sqlite$', 'OpenAI Codex', 'codex-state'),
    (r'/\.codex/config\.toml$', 'OpenAI Codex', 'codex-config'),
    (r'/\.cursor/projects/[^/]+/agent-transcripts/.+\.jsonl$', 'Cursor', 'cursor-transcript'),
    (r'/\.cursor/projects/[^/]+/mcps/', 'Cursor', 'cursor-mcpcache'),
    (r'/\.cursor/hooks\.json$', 'Cursor', 'hooks-json'),
    (r'/cursor/user/globalstorage/state\.vscdb$', 'Cursor', 'cursor-state'),
    (r'/\.cursor/ai-tracking/ai-code-tracking\.db$', 'Cursor', 'cursor-tracking'),
    (r'/\.cursor/cli-config\.json$|/cursor/user/settings\.json$', 'Cursor', 'cursor-settings'),
    (r'/\.copilot/(history-)?session-state/.+\.jsonl$', 'GitHub Copilot CLI', 'copilot-events'),
    (r'/\.copilot/mcp-config\.json$', 'GitHub Copilot CLI', 'mcp-json'),
    (r'/\.copilot/settings\.json$', 'GitHub Copilot CLI', 'hooks-json'),
    (r'/\.copilot/permissions-config\.json$', 'GitHub Copilot CLI', 'copilot-perms'),
    (r'/code/user/workspacestorage/[^/]+/chatsessions/.+\.jsonl?$|/emptywindowchatsessions/.+\.jsonl?$', 'VS Code Copilot Chat', 'vscode-chat'),
    (r'/code/user/mcp\.json$', 'VS Code Copilot Chat', 'mcp-json'),
    (r'/\.gemini/antigravity/mcp_config\.json$', 'Antigravity', 'mcp-json'),
    (r'/\.gemini/settings\.json$', 'Gemini CLI', 'gemini-settings'),
    (r'/\.gemini/tmp/.+\.jsonl?$', 'Gemini CLI', 'gemini-chat'),
    (r'/\.codeium/windsurf/mcp_config\.json$', 'Windsurf', 'mcp-json'),
    (r'/saoudrizwan\.claude-dev/settings/cline_mcp_settings\.json$', 'Cline', 'mcp-json'),
    (r'/saoudrizwan\.claude-dev/tasks/[^/]+/api_conversation_history\.json$', 'Cline', 'cline-task'),
    (r'/cursor/user/mcp\.json$|/\.cursor/mcp\.json$', 'Cursor', 'mcp-json'),
    (r'/\.mcp\.json$|/\.vscode/mcp\.json$|/\.github/mcp\.json$', 'Project files', 'mcp-json'),
    (r'/\.cursor/hooks\.json$', 'Project files', 'hooks-json'),
    (r'/(claude|claude\.local|agents|gemini|skill|copilot-instructions)\.md$|/\.(cursorrules|windsurfrules|clinerules)$|'
     r'/rules/[^/]+\.mdc$|\.instructions\.md$|/\.claude/(agents|commands|rules|skills)/.+\.md$|/memories/global_rules\.md$|'
     r'/\.codex/rules/', None, 'instructions'),
]
RULES = [(re.compile(r, re.I), a, k) for r, a, k in RULES]
AGENT_HINTS = [('/.claude', 'Claude Code'), ('/.codex', 'OpenAI Codex'), ('/.cursor', 'Cursor'), ('/.copilot', 'GitHub Copilot CLI'),
               ('/.gemini/antigravity', 'Antigravity'), ('/.gemini', 'Gemini CLI'), ('/.codeium', 'Windsurf'), ('/.windsurf', 'Windsurf'),
               ('claude-dev', 'Cline'), ('/.clinerules', 'Cline')]


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def iso_ms(v):
    try:
        v = float(v)
        if v > 1e14:
            v /= 1e6
        elif v > 1e11:
            v /= 1e3
        return dt.datetime.fromtimestamp(v, dt.timezone.utc).isoformat().replace('+00:00', 'Z')
    except (TypeError, ValueError, OverflowError, OSError):
        return str(v or '')


def parse_iso(s):
    try:
        return dt.datetime.fromisoformat(str(s).replace('Z', '+00:00'))
    except ValueError:
        return None


def clip(s, n=300):
    s = re.sub(r'[\r\n\t]+', ' ', str(s if s is not None else '')).strip()
    return s if len(s) <= n else s[:n] + '...'


def fsp(path):
    """Long-path safe name on Windows."""
    if os.name == 'nt' and len(path) >= 240 and not path.startswith('\\\\?\\'):
        return '\\\\?\\' + os.path.abspath(path)
    return path


def read_text(path, limit=32 * 1024 * 1024):
    try:
        if os.path.getsize(fsp(path)) > limit:
            return None
        with open(fsp(path), 'r', encoding='utf-8-sig', errors='replace') as f:
            return f.read()
    except OSError:
        return None


def loads_loose(text):
    if not text:
        return None
    t = re.sub(r'(?m)^\s*//.*$', '', text)
    t = re.sub(r',(\s*[}\]])', r'\1', t)
    try:
        return json.loads(t)
    except ValueError:
        return None


def jsonl(path):
    try:
        with open(fsp(path), 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                yield line
    except OSError:
        return


def user_of(path):
    m = re.search(r'/(?:users|home)/([^/]+)/', path, re.I)
    if m:
        return m.group(1)
    return 'root' if '/root/' in path else '?'


def hidden_unicode(text):
    if not text:
        return None
    body = text[1:] if text.startswith('\ufeff') else text
    hits = HIDDEN.findall(body) + (['\ufeff'] * body.count('\ufeff'))
    if not hits:
        return None
    kinds, decoded = set(), []
    for ch in hits:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            kinds.add('tag')
            if 0x20 <= cp - 0xE0000 <= 0x7E:
                decoded.append(chr(cp - 0xE0000))
        elif 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            kinds.add('bidi')
        elif cp == 0xFEFF:
            kinds.add('inner-BOM')
        else:
            kinds.add('zero-width')
    return {'count': len(hits), 'kinds': ','.join(sorted(kinds)), 'decoded': ''.join(decoded),
            'severe': bool(kinds & {'tag', 'bidi'})}


class Triage:
    def __init__(self):
        self.findings, self.activity, self.mcp, self.hooks = [], [], [], []
        self.tools = {}
        self.files = []
        self.retention = {}

    # ------------------------------------------------------------------ records
    def finding(self, sev, agent, user, title, detail, src):
        self.findings.append({'Severity': sev, 'Agent': agent, 'User': user, 'Finding': title,
                              'Detail': clip(detail, 600), 'Source': src})

    def act(self, ts, agent, user, session, actor, tool, detail, cwd, src):
        self.activity.append({'TimestampUtc': ts or '', 'Agent': agent, 'User': user, 'Session': session, 'Actor': actor,
                              'Tool': tool, 'Detail': clip(detail, 400), 'Cwd': cwd or '', 'Source': src})

    # ------------------------------------------------------------------ discovery
    def match(self, norm):
        for rx, agent, kind in RULES:
            if rx.search(norm):
                return agent or next((a for h, a in AGENT_HINTS if h in norm.lower()), 'Project files'), kind
        return None

    def add_file(self, path, norm):
        m = self.match(norm)
        if m:
            self.files.append({'path': path, 'norm': norm, 'agent': m[0], 'kind': m[1], 'user': user_of(norm)})
        return bool(m)

    def classify(self, root):
        for dirpath, _dirs, names in os.walk(root):
            for n in names:
                p = os.path.join(dirpath, n)
                self.add_file(p, p.replace('\\', '/'))

    def of(self, *kinds):
        return [f for f in self.files if f['kind'] in kinds]

    # ------------------------------------------------------------------ MCP
    def mcp_flags(self, cmd, args, url, env):
        flags, sev = [], 'Info'
        joined = ' '.join([cmd or ''] + list(args))
        if cmd and RX_SHELL.search(cmd):
            if any(RX_INLINE.match(a or '') for a in args):
                flags.append('shell-inline-code'); sev = 'High'
            else:
                flags.append('shell-launcher'); sev = 'Medium'
        if RX_CRADLE.search(joined):
            flags.append('download-or-decode'); sev = 'High'
        if cmd and RX_TEMP.search(cmd):
            flags.append('binary-in-temp-or-public'); sev = 'High'
        if cmd and RX_RUNNER.search(cmd):
            pkg = next((a for a in args if a and not a.startswith('-')), '')
            if pkg and not re.match(r'^@?[^@]+@\d', pkg):
                flags.append('unpinned-package:' + pkg)
                if sev == 'Info':
                    sev = 'Low'
        if url:
            host = re.sub(r'^[a-z]+://', '', url, flags=re.I).split('/')[0].split(':')[0]
            if host not in ('localhost', '127.0.0.1', '[', '::1'):
                flags.append('remote:' + host)
        for k, v in (env or {}).items():
            v = str(v)
            if RX_SECRET.search(k) and len(v) >= 12 and not re.match(r'^(\$|%|\{\{|<)', v):
                flags.append('plaintext-secret:' + k)
                if sev in ('Info', 'Low'):
                    sev = 'Medium'
        return sev, '; '.join(flags)

    def add_server(self, agent, user, src, scope, name, d):
        if not isinstance(d, dict):
            return
        cmd = str(d.get('command') or '')
        args = [str(a) for a in (d.get('args') or [])] if isinstance(d.get('args'), list) else []
        url = str(d.get('url') or d.get('serverUrl') or d.get('httpUrl') or '')
        env = d.get('env') if isinstance(d.get('env'), dict) else {}
        sev, flags = self.mcp_flags(cmd, args, url, env)
        self.mcp.append({'Agent': agent, 'User': user, 'Server': name, 'Transport': d.get('type') or ('http' if url else 'stdio'),
                         'Command': cmd, 'Args': clip(' '.join(args), 400), 'Url': url, 'EnvNames': ','.join(env),
                         'Severity': sev, 'Flags': flags, 'Scope': scope, 'Source': src})
        if sev in ('High', 'Medium'):
            self.finding(sev, agent, user, "MCP server '%s' looks risky" % name, '%s | %s %s %s' % (flags, cmd, ' '.join(args), url), src)

    def walk_servers(self, node, trail, vscode, out, depth=0):
        if depth > 6:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, dict) and (k in ('mcpServers', 'mcp_servers') or (vscode and k == 'servers')):
                    for name, d in v.items():
                        out.append((trail or 'user', name, d))
                elif isinstance(v, (dict, list)):
                    self.walk_servers(v, trail + '/' + k, vscode, out, depth + 1)
        elif isinstance(node, list):
            for i in node:
                self.walk_servers(i, trail, vscode, out, depth + 1)

    # ------------------------------------------------------------------ hooks
    def hook_cmds(self, node, event, out):
        if isinstance(node, list):
            for i in node:
                self.hook_cmds(i, event, out)
        elif isinstance(node, dict):
            for k in ('command', 'bash', 'powershell', 'cmd'):
                if isinstance(node.get(k), str) and node[k]:
                    out.append((event, node[k]))
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    self.hook_cmds(v, event or k, out)

    def add_hooks(self, agent, user, src, node):
        out = []
        self.hook_cmds(node, '', out)
        for event, cmd in out:
            sev, fl = 'Low', ''
            if RX_CRADLE.search(cmd):
                sev, fl = 'High', 'download-or-decode'
            elif RX_TEMP.search(cmd):
                sev, fl = 'High', 'binary-in-temp-or-public'
            self.hooks.append({'Agent': agent, 'User': user, 'Event': event, 'Command': clip(cmd, 500), 'Severity': sev, 'Flags': fl, 'Source': src})
            self.finding(sev, agent, user, 'Agent hook runs a download/decode command' if sev == 'High' else 'Agent hook configured',
                         '%s: %s' % (event, cmd), src)

    # ------------------------------------------------------------------ tool descriptions
    def tool_desc(self, agent, user, tool, desc, ts, session, src):
        if not desc:
            return
        h = hashlib.sha256(desc.encode('utf-8', 'replace')).hexdigest()[:16]
        e = self.tools.setdefault((agent, user, tool), {'first': ts, 'last': ts, 'versions': {}})
        if ts and (not e['first'] or ts < e['first']):
            e['first'] = ts
        if ts and ts > (e['last'] or ''):
            e['last'] = ts
        if h in e['versions']:
            return
        why = []
        strong, weak, hid = RX_INJECT.search(desc), RX_INJECT_WEAK.search(desc), hidden_unicode(desc)
        if strong:
            why.append("injection marker '%s'" % strong.group(0))
        if weak:
            why.append("hides activity from the user: '%s'" % weak.group(0))
        if hid:
            why.append('hidden Unicode (%s) %s' % (hid['kinds'], hid['decoded']))
        if why:
            sev = 'High' if strong or (hid and hid['severe']) else 'Medium'
            self.finding(sev, agent, user, 'Tool description seen by the model looks poisoned: ' + tool, '; '.join(why) + ' | ' + desc, src)
        e['versions'][h] = {'ts': ts, 'session': session, 'src': src, 'flags': '; '.join(why), 'desc': desc}

    # ------------------------------------------------------------------ analyzers
    def configs(self):
        for f in self.of('mcp-json', 'claude-global', 'gemini-settings'):
            text = read_text(f['path'])
            obj = loads_loose(text)
            if obj is None:
                continue
            out = []
            self.walk_servers(obj, '', f['norm'].lower().endswith('/mcp.json'), out)
            for scope, name, d in out:
                self.add_server(f['agent'], f['user'], f['path'], scope, name, d)
            if f['kind'] == 'gemini-settings':
                if isinstance(obj, dict) and obj.get('hooks'):
                    self.add_hooks(f['agent'], f['user'], f['path'], obj['hooks'])
                m = re.search(r'"(yolo|autoAccept)"\s*:\s*true|"approvalMode"\s*:\s*"yolo"', text or '', re.I)
                if m:
                    self.finding('Medium', f['agent'], f['user'], 'Gemini CLI auto-approves tool calls (YOLO)', m.group(0), f['path'])
        for f in self.of('codex-config'):
            text = read_text(f['path']) or ''
            section, srv, servers = '', None, {}
            for line in text.splitlines():
                l = line.strip()
                m = re.match(r'^\[(.+)\]$', l)
                if m:
                    section = m.group(1)
                    sm = re.match(r'^mcp_servers\."?([^".]+)"?$', section)
                    srv = sm.group(1) if sm else None
                    if srv:
                        servers[srv] = {'command': '', 'args': [], 'url': ''}
                    continue
                if srv:
                    m = re.match(r'''^(command|url)\s*=\s*["']([^"']*)["']''', l)
                    if m:
                        servers[srv][m.group(1)] = m.group(2)
                    m = re.match(r'^args\s*=\s*\[(.*)\]', l)
                    if m:
                        servers[srv]['args'] = [a or b for a, b in re.findall(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'', m.group(1))]
                elif not section:
                    if re.match(r'^approval_policy\s*=\s*"never"', l):
                        self.finding('Medium', 'OpenAI Codex', f['user'], 'Codex configured to never ask for approval', l, f['path'])
                    if re.match(r'^sandbox_mode\s*=\s*"danger-full-access"', l):
                        self.finding('Medium', 'OpenAI Codex', f['user'], 'Codex sandbox disabled (danger-full-access)', l, f['path'])
                    m = re.match(r'^notify\s*=\s*(.+)$', l)
                    if m:
                        sev = 'High' if RX_CRADLE.search(m.group(1)) else 'Low'
                        self.hooks.append({'Agent': 'OpenAI Codex', 'User': f['user'], 'Event': 'notify', 'Command': clip(m.group(1), 500),
                                           'Severity': sev, 'Flags': '', 'Source': f['path']})
                        self.finding(sev, 'OpenAI Codex', f['user'], 'Codex notify program configured', m.group(1), f['path'])
            for name, d in servers.items():
                self.add_server('OpenAI Codex', f['user'], f['path'], 'config.toml', name, d)
        current = {(r['User'], r['Server']) for r in self.mcp if r['Source'].replace('\\', '/').endswith('/.claude.json')}
        for f in self.of('claude-global-backup'):
            out = []
            self.walk_servers(loads_loose(read_text(f['path'])), '', False, out)
            for _scope, name, d in out:
                if (f['user'], name) not in current:
                    current.add((f['user'], name))
                    d = d if isinstance(d, dict) else {}
                    self.finding('Medium', 'Claude Code', f['user'], "MCP server '%s' was removed (still in a .claude.json backup)" % name,
                                 '%s %s %s' % (d.get('command', ''), ' '.join(map(str, d.get('args') or [])), d.get('url', '')), f['path'])
        for f in self.of('claude-settings', 'hooks-json', 'cursor-settings'):
            text = read_text(f['path'])
            obj = loads_loose(text)
            if not isinstance(obj, dict):
                continue
            if obj.get('hooks'):
                self.add_hooks(f['agent'], f['user'], f['path'], obj['hooks'])
            if f['kind'] == 'claude-settings':
                perm = obj.get('permissions') or {}
                if perm.get('defaultMode') == 'bypassPermissions':
                    self.finding('Medium', 'Claude Code', f['user'], 'Claude Code defaults to bypassPermissions', 'permissions.defaultMode = bypassPermissions', f['path'])
                if obj.get('skipDangerousModePermissionPrompt') is True:
                    self.finding('Low', 'Claude Code', f['user'], 'Bypass-mode warning was accepted and silenced', 'skipDangerousModePermissionPrompt = true', f['path'])
                for rule in perm.get('allow') or []:
                    if re.match(r'^(Bash|PowerShell)(\(\*\)|\(\*:\*\))?$|^\*$', str(rule)):
                        self.finding('Medium', 'Claude Code', f['user'], 'Blanket shell permission rule', 'allow: %s' % rule, f['path'])
                if 'cleanupPeriodDays' in obj:
                    try:
                        days = int(obj['cleanupPeriodDays'])
                        self.retention[f['user']] = days
                        if days < 7:
                            self.finding('Medium', 'Claude Code', f['user'], 'Transcript retention shortened', 'cleanupPeriodDays = %d (default 30)' % days, f['path'])
                    except (TypeError, ValueError):
                        pass
            if f['kind'] == 'cursor-settings':
                m = re.search(r'"[^"]*(yolo|autorun|auto-run)[^"]*"\s*:\s*true|"Shell\(\*\)"', text or '', re.I)
                if m:
                    self.finding('Medium', 'Cursor', f['user'], 'Cursor auto-runs agent commands', m.group(0), f['path'])
        for f in self.of('copilot-perms'):
            obj = loads_loose(read_text(f['path']))
            if isinstance(obj, dict) and isinstance(obj.get('locations'), dict):
                self.finding('Info', f['agent'], f['user'], 'Copilot CLI saved approvals', '%d project locations with saved tool approvals' % len(obj['locations']), f['path'])

    def unicode_scan(self):
        for f in self.of('instructions', 'mcp-json', 'cursor-mcpcache'):
            if not TEXT_EXT.search(f['norm']):
                continue
            text = read_text(f['path'], 5 * 1024 * 1024)
            hid = hidden_unicode(text)
            if hid:
                d = '%d hidden characters (%s)' % (hid['count'], hid['kinds'])
                if hid['decoded']:
                    d += " | decoded tag text: '%s'" % hid['decoded']
                self.finding('High' if hid['severe'] else 'Medium', f['agent'], f['user'], 'Hidden Unicode in an agent instruction/config file', d, f['path'])
            if f['kind'] == 'cursor-mcpcache' and text:
                m = RX_INJECT.search(text)
                if m:
                    self.finding('High', 'Cursor', f['user'], 'Cached MCP tool metadata contains an injection marker', "'%s' | %s" % (m.group(0), text), f['path'])

    def claude(self):
        sessions, bypass = set(), {}
        for f in self.of('claude-transcript'):
            sid = os.path.splitext(posixpath.basename(f['norm']))[0]
            if '/subagents/' not in f['norm']:
                sessions.add((f['user'], sid))
            n_bypass = 0
            for line in jsonl(f['path']):
                if '"permissionMode":"bypassPermissions"' in line:
                    n_bypass += 1
                if '"type":"api-request-shape"' in line:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    for t in (r.get('shape') or {}).get('tools') or []:
                        if str(t.get('name', '')).startswith('mcp__'):
                            self.tool_desc('Claude Code', f['user'], t['name'], t.get('description') or '', r.get('timestamp', ''), sid, f['path'])
                    continue
                if '"type":"assistant"' in line and '"tool_use"' in line:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    for c in (r.get('message') or {}).get('content') or []:
                        if isinstance(c, dict) and c.get('type') == 'tool_use':
                            inp = c.get('input') or {}
                            detail = next((inp[k] for k in ('command', 'file_path', 'path', 'url', 'pattern', 'query', 'prompt') if inp.get(k)), None)
                            self.act(r.get('timestamp'), 'Claude Code', f['user'], sid, 'subagent' if r.get('isSidechain') else 'agent',
                                     c.get('name'), detail if detail is not None else json.dumps(inp)[:400], r.get('cwd'), f['path'])
                    continue
                if '"type":"user"' in line and '"tool_result"' not in line and '"userType":"external"' in line:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    content = (r.get('message') or {}).get('content')
                    if isinstance(content, str) and content and not content.startswith('<'):
                        self.act(r.get('timestamp'), 'Claude Code', f['user'], sid, 'user', 'PROMPT', content, r.get('cwd'), f['path'])
                    continue
                if '"hookInfos"' in line:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    for hi in r.get('hookInfos') or []:
                        self.act(r.get('timestamp'), 'Claude Code', f['user'], sid, 'hook', 'HOOK', hi.get('command'), r.get('cwd'), f['path'])
            if n_bypass:
                bypass.setdefault(f['user'], []).append(sid)
        for u, ids in bypass.items():
            self.finding('Medium', 'Claude Code', u, 'Sessions ran with all permission checks bypassed',
                         '%d sessions recorded permissionMode=bypassPermissions, e.g. %s' % (len(ids), ', '.join(ids[:3])), '')
        for f in self.of('claude-history'):
            last, proj = {}, {}
            for line in jsonl(f['path']):
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                sid, ts = str(r.get('sessionId') or ''), r.get('timestamp')
                when = iso_ms(ts) if isinstance(ts, (int, float)) else str(ts or '')
                self.act(when, 'Claude Code', f['user'], sid, 'user', 'PROMPT (history)', r.get('display'), r.get('project'), f['path'])
                if sid and when > last.get(sid, ''):
                    last[sid], proj[sid] = when, r.get('project', '')
            days, aged = self.retention.get(f['user'], 30), 0
            for sid, when in last.items():
                if (f['user'], sid) in sessions:
                    continue
                t = parse_iso(when)
                age = (now_utc() - t).days if t else 0
                if age > days + 1:
                    aged += 1
                else:
                    self.finding('High', 'Claude Code', f['user'], 'Transcript missing for a recent session',
                                 'session %s last prompt %s in %s: history.jsonl has it, projects/ does not (deleted or purged; retention is %d days)'
                                 % (sid, when, proj.get(sid), days), f['path'])
            if aged:
                self.finding('Info', 'Claude Code', f['user'], 'Sessions aged out by the retention sweep',
                             '%d sessions in history.jsonl are older than %d days and have no transcript (expected behaviour)' % (aged, days), f['path'])
        for f in self.of('claude-lastcleanup'):
            self.finding('Info', 'Claude Code', f['user'], 'Retention sweep last ran',
                         '%s - every launch can delete transcripts older than cleanupPeriodDays' % (read_text(f['path']) or '').strip(), f['path'])

    def codex(self):
        ids, open_ = set(), {}
        rollouts = set()
        for f in self.of('codex-rollout'):
            base = posixpath.basename(f['norm'])
            rollouts.add(base)
            sid = re.sub(r'^rollout-[0-9T:\-]+-', '', os.path.splitext(base)[0])
            ids.add((f['user'], sid))
            never = full = 0
            for line in jsonl(f['path']):
                if '"type":"turn_context"' in line:
                    never += '"approval_policy":"never"' in line
                    full += '"danger-full-access"' in line
                    continue
                if not any(k in line for k in ('"exec_command_end"', '"patch_apply_end"', '"user_message"', '"mcp_tool_call_end"', '"session_meta"')):
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                p, ts = r.get('payload') or {}, r.get('timestamp', '')
                pt = p.get('type')
                if pt == 'exec_command_end':
                    cmd = p.get('command') or []
                    if isinstance(cmd, list):
                        text = cmd[-1] if len(cmd) >= 3 and str(cmd[1]) in ('-Command', '-c', '-lc') else ' '.join(map(str, cmd))
                    else:
                        text = str(cmd)
                    self.act(ts, 'OpenAI Codex', f['user'], sid, 'agent', 'shell (exit %s)' % p.get('exit_code'), text, p.get('cwd'), f['path'])
                elif pt == 'patch_apply_end':
                    self.act(ts, 'OpenAI Codex', f['user'], sid, 'agent', 'apply_patch', ', '.join((p.get('changes') or {}).keys()), '', f['path'])
                elif pt == 'user_message':
                    self.act(ts, 'OpenAI Codex', f['user'], sid, 'user', 'PROMPT', p.get('message'), '', f['path'])
                elif pt == 'mcp_tool_call_end':
                    inv = p.get('invocation') or {}
                    self.act(ts, 'OpenAI Codex', f['user'], sid, 'agent', 'mcp:%s/%s' % (inv.get('server'), inv.get('tool')),
                             json.dumps(inv.get('arguments'))[:400], '', f['path'])
                elif r.get('type') == 'session_meta':
                    for t in p.get('dynamic_tools') or []:
                        self.tool_desc('OpenAI Codex', f['user'], t.get('name', ''), t.get('description') or '', ts, sid, f['path'])
            if never or full:
                open_.setdefault(f['user'], []).append('%s (%d never / %d full-access turns)' % (sid, never, full))
        for u, rows in open_.items():
            self.finding('Medium', 'OpenAI Codex', u, 'Codex sessions ran without approvals or sandbox', '%d sessions, e.g. %s' % (len(rows), '; '.join(rows[:3])), '')
        for f in self.of('codex-index'):
            for line in jsonl(f['path']):
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get('id') and (f['user'], r['id']) not in ids:
                    self.finding('Medium', 'OpenAI Codex', f['user'], 'Codex thread has no rollout file',
                                 "thread %s '%s' updated %s: indexed but its transcript is gone" % (r['id'], r.get('thread_name'), r.get('updated_at')), f['path'])
        for f in self.of('codex-state'):
            try:
                con = sqlite3.connect('file:%s?mode=ro&immutable=1' % f['path'].replace('\\', '/'), uri=True)
                rows = con.execute('select id, rollout_path, created_at, updated_at, cwd, title, sandbox_policy, approval_mode from threads').fetchall()
            except sqlite3.Error:
                continue
            for tid, rp, created, updated, cwd, title, sandbox, approval in rows:
                if rp and os.path.basename(str(rp).replace('\\', '/')) not in rollouts:
                    self.finding('Medium', 'OpenAI Codex', f['user'], 'Codex thread has no rollout file',
                                 "state DB thread %s '%s' (%s, updated %s) points to %s, which is not in the evidence" % (tid, title, cwd, iso_ms(updated), rp), f['path'])
                if str(approval) == 'never' or 'danger-full-access' in str(sandbox):
                    self.act(iso_ms(created), 'OpenAI Codex', f['user'], tid, 'config', 'thread posture', 'approval=%s sandbox=%s' % (approval, clip(sandbox, 120)), cwd, f['path'])

    def cursor(self):
        for f in self.of('cursor-transcript'):
            sid = os.path.splitext(posixpath.basename(f['norm']))[0]
            mtime = iso_ms(os.path.getmtime(fsp(f['path'])))
            for i, line in enumerate(jsonl(f['path']), 1):
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                for c in (r.get('message') or {}).get('content') or []:
                    if c.get('type') == 'tool_use':
                        inp = c.get('input') or {}
                        detail = next((inp[k] for k in ('command', 'path', 'glob_pattern', 'pattern', 'search_term', 'url') if inp.get(k)), '')
                        self.act('(line %d; file mtime %s)' % (i, mtime), 'Cursor', f['user'], sid, 'agent', c.get('name'), detail, inp.get('working_directory'), f['path'])
                    elif r.get('role') == 'user' and c.get('type') == 'text':
                        self.act('(line %d; file mtime %s)' % (i, mtime), 'Cursor', f['user'], sid, 'user', 'PROMPT', c.get('text'), '', f['path'])
        for f in self.of('cursor-state'):
            try:
                con = sqlite3.connect('file:%s?mode=ro&immutable=1' % f['path'].replace('\\', '/'), uri=True)
                rows = con.execute("select key, value from cursorDiskKV where key like 'bubbleId:%'").fetchall()
            except sqlite3.Error:
                continue
            for key, val in rows:
                try:
                    b = json.loads(val)
                except (TypeError, ValueError):
                    continue
                parts = key.split(':')
                comp = parts[1] if len(parts) > 2 else ''
                ts = b.get('createdAt') or ''
                if isinstance(ts, (int, float)):
                    ts = iso_ms(ts)
                t = b.get('toolFormerData') or {}
                if t.get('name'):
                    try:
                        params = json.loads(t.get('params') or t.get('rawArgs') or '{}')
                    except ValueError:
                        params = {}
                    try:
                        result = json.loads(t.get('result') or '{}')
                    except ValueError:
                        result = {}
                    params = params if isinstance(params, dict) else {}
                    result = result if isinstance(result, dict) else {}
                    detail = next((params[k] for k in ('command', 'relativeWorkspacePath', 'targetFile', 'target_file', 'path', 'query', 'globPattern', 'pattern', 'url') if params.get(k)), '')
                    status = str(t.get('status') or '')
                    tool = t['name'] + (' (%s)' % status if status and status != 'completed' else '')
                    if result.get('rejected'):
                        tool += ' REJECTED BY USER'
                    self.act(ts, 'Cursor', f['user'], comp, 'agent', tool, detail if isinstance(detail, str) else json.dumps(detail), params.get('cwd'), f['path'])
                elif b.get('type') == 1 and b.get('text'):
                    self.act(ts, 'Cursor', f['user'], comp, 'user', 'PROMPT', b.get('text'), '', f['path'])
        for f in self.of('cursor-tracking'):
            try:
                con = sqlite3.connect('file:%s?mode=ro&immutable=1' % f['path'].replace('\\', '/'), uri=True)
                for path, comp, conv, model, deleted in con.execute('select gitPath, composerId, conversationId, model, deletedAt from ai_deleted_files'):
                    self.act(iso_ms(deleted), 'Cursor', f['user'], conv or comp, 'agent', 'DELETED FILE (ai-tracking)', path, '', f['path'])
                for conv, title, tldr, model, upd in con.execute('select conversationId, title, tldr, model, updatedAt from conversation_summaries'):
                    self.act(iso_ms(upd), 'Cursor', f['user'], conv, 'summary', 'conversation summary', '%s - %s' % (title, tldr), '', f['path'])
            except sqlite3.Error:
                continue

    def generic_events(self):
        for f in self.of('copilot-events', 'gemini-chat'):
            sid = posixpath.basename(posixpath.dirname(f['norm']))
            for line in jsonl(f['path']):
                if '"command"' not in line and '"toolName"' not in line:
                    continue
                m = re.search(r'"command"\s*:\s*"((?:[^"\\]|\\.){1,400})', line)
                t = re.search(r'"(timestamp|time|createdAt)"\s*:\s*"([^"]+)"', line)
                n = re.search(r'"(toolName|name)"\s*:\s*"([^"]+)"', line)
                cmd = ''
                if m:
                    try:
                        cmd = json.loads('"%s"' % m.group(1))
                    except ValueError:
                        cmd = m.group(1)
                self.act(t.group(2) if t else '', f['agent'], f['user'], sid, 'agent', n.group(2) if n else 'tool', cmd, '', f['path'])
        for f in self.of('vscode-chat'):
            text = read_text(f['path'])
            if not text:
                continue
            obj = loads_loose(text)
            if obj is None:
                try:
                    obj = json.loads(text.splitlines()[0])
                except (ValueError, IndexError):
                    continue
            if isinstance(obj, dict) and isinstance(obj.get('v'), dict):
                obj = obj['v']
            if not isinstance(obj, dict):
                continue
            sid = obj.get('sessionId') or posixpath.basename(f['norm'])
            for q in obj.get('requests') or []:
                ts = iso_ms(q.get('timestamp')) if q.get('timestamp') else ''
                msg = (q.get('message') or {}).get('text')
                if msg:
                    self.act(ts, 'VS Code Copilot Chat', f['user'], sid, 'user', 'PROMPT', msg, '', f['path'])
                for part in q.get('response') or []:
                    if isinstance(part, dict) and part.get('kind') in ('toolInvocationSerialized', 'toolInvocation'):
                        im = part.get('invocationMessage')
                        im = im.get('value') if isinstance(im, dict) else im
                        self.act(ts, 'VS Code Copilot Chat', f['user'], sid, 'agent', part.get('toolId') or 'tool', im, '', f['path'])
        for f in self.of('cline-task'):
            obj = loads_loose(read_text(f['path']))
            sid = posixpath.basename(posixpath.dirname(f['norm']))
            mtime = iso_ms(os.path.getmtime(fsp(f['path'])))
            for msg in obj if isinstance(obj, list) else []:
                for c in msg.get('content') or [] if isinstance(msg.get('content'), list) else []:
                    if isinstance(c, dict) and c.get('type') == 'tool_use':
                        inp = c.get('input') or {}
                        detail = next((inp[k] for k in ('command', 'path', 'url', 'regex') if inp.get(k)), json.dumps(inp)[:300])
                        self.act('(file mtime %s)' % mtime, 'Cline', f['user'], sid, 'agent', c.get('name'), detail, '', f['path'])

    def run(self):
        self.configs()
        self.unicode_scan()
        self.claude()
        self.codex()
        self.cursor()
        self.generic_events()
        for (agent, user, tool), e in self.tools.items():
            if len(e['versions']) > 1:
                when = ' -> '.join(sorted(v['ts'] or '?' for v in e['versions'].values()))
                self.finding('Low', agent, user, 'MCP tool description changed between sessions: ' + tool,
                             '%d versions first seen at %s; diff them in mcp_tools_seen.csv (a silent change is how a rug pull looks)' % (len(e['versions']), when), '')

    # ------------------------------------------------------------------ output
    def write(self, out):
        os.makedirs(out, exist_ok=True)
        self.findings.sort(key=lambda f: (SEV_RANK[f['Severity']], f['Agent'], f['Finding']))
        self.activity.sort(key=lambda a: a['TimestampUtc'])
        tools = []
        for (agent, user, tool), e in self.tools.items():
            for h, v in e['versions'].items():
                tools.append({'Agent': agent, 'User': user, 'Tool': tool, 'Version': h, 'Versions': len(e['versions']),
                              'VersionFirstSeenUtc': v['ts'], 'ToolFirstSeenUtc': e['first'], 'ToolLastSeenUtc': e['last'],
                              'Flags': v['flags'], 'Session': v['session'], 'Description': clip(v['desc'], 2000), 'Source': v['src']})
        tables = {'findings.csv': self.findings, 'agent_activity.csv': self.activity, 'mcp_servers.csv': self.mcp,
                  'hooks.csv': self.hooks, 'mcp_tools_seen.csv': tools}
        for name, rows in tables.items():
            if not rows:
                continue
            with open(os.path.join(out, name), 'w', newline='', encoding='utf-8-sig') as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
        counts = {k: sum(1 for f in self.findings if f['Severity'] == k) for k in SEV_RANK}
        agents = {}
        for f in self.files:
            agents[f['agent']] = agents.get(f['agent'], 0) + 1
        summary = {'kit': 'Agent Triage Kit analyzer 1.0', 'generatedUtc': now_utc().isoformat(), 'files': len(self.files),
                   'agents': agents, 'mcpServers': len(self.mcp), 'hooks': len(self.hooks), 'activityRows': len(self.activity), 'findings': counts}
        with open(os.path.join(out, 'summary.json'), 'w', encoding='utf-8') as fh:
            json.dump(summary, fh, indent=2)
        self.html(out, summary, tables)
        return summary

    def html(self, out, summary, tables):
        def table(rows, cols, limit=5000):
            if not rows:
                return '<p class="empty">Nothing here.</p>'
            head = ''.join('<th>%s</th>' % html.escape(c) for c in cols)
            body = []
            for r in rows[:limit]:
                cls = ' class="sev-%s"' % r.get('Severity', '').lower() if r.get('Severity') else ''
                body.append('<tr%s>%s</tr>' % (cls, ''.join('<td>%s</td>' % html.escape(str(r.get(c, ''))) for c in cols)))
            more = '<p class="empty">Showing %d of %d rows. The CSV has all of them.</p>' % (limit, len(rows)) if len(rows) > limit else ''
            return '<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>%s' % (head, ''.join(body), more)
        f = summary['findings']
        cards = ''.join('<div class="card sev-%s"><b>%d</b><span>%s</span></div>' % (k.lower(), f[k], k) for k in SEV_RANK)
        agents = ''.join('<li>%s <em>%d files</em></li>' % (html.escape(a), n) for a, n in sorted(summary['agents'].items(), key=lambda x: -x[1]))
        doc = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent triage report</title><style>
:root{--bg:#0b1220;--panel:#111a2e;--line:#22304d;--text:#e2e8f0;--muted:#94a3b8;--high:#fb7185;--med:#f59e0b;--low:#60a5fa;--info:#64748b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,sans-serif;padding:24px}
h1{margin:0 0 4px;font-size:22px}h2{margin:28px 0 8px;font-size:16px;color:#93c5fd}.muted{color:var(--muted)}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 16px;min-width:110px}
.card b{display:block;font-size:24px}.card span{color:var(--muted)}.card.sev-high b{color:var(--high)}.card.sev-medium b{color:var(--med)}.card.sev-low b{color:var(--low)}
ul{columns:3;color:var(--muted)}em{color:var(--text);font-style:normal}input{width:100%%;max-width:420px;padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--text)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;margin-top:8px}table{border-collapse:collapse;width:100%%;font-size:12.5px}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;max-width:520px;word-break:break-word}
th{background:var(--panel);position:sticky;top:0}tr.sev-high td:first-child{color:var(--high);font-weight:600}tr.sev-medium td:first-child{color:var(--med);font-weight:600}
tr.sev-low td:first-child{color:var(--low)}.empty{color:var(--muted)}footer{margin-top:32px;color:var(--muted);font-size:12px}
</style></head><body><h1>Agent triage report</h1><div class="muted">Generated %s &middot; %d artifact files &middot; %d MCP servers &middot; %d hooks &middot; %d activity rows</div>
<div class="cards">%s</div><ul>%s</ul><input id="q" placeholder="Filter every table (user, tool, path, command...)">
<h2>Findings</h2><div class="wrap">%s</div><h2>MCP servers</h2><div class="wrap">%s</div><h2>Hooks</h2><div class="wrap">%s</div>
<h2>Agent activity (first 5,000 rows)</h2><div class="wrap">%s</div>
<footer>Agent Triage Kit &middot; thelocalh0st.com &middot; verify every finding against the source file listed.</footer>
<script>document.getElementById('q').addEventListener('input',function(e){var q=e.target.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(function(r){r.style.display=r.textContent.toLowerCase().indexOf(q)<0?'none':''})})</script>
</body></html>''' % (html.escape(summary['generatedUtc']), summary['files'], summary['mcpServers'], summary['hooks'], summary['activityRows'], cards, agents,
                     table(tables['findings.csv'], ['Severity', 'Agent', 'User', 'Finding', 'Detail', 'Source']),
                     table(tables['mcp_servers.csv'], ['Severity', 'Agent', 'User', 'Server', 'Transport', 'Command', 'Args', 'Url', 'Flags', 'Source']),
                     table(tables['hooks.csv'], ['Severity', 'Agent', 'User', 'Event', 'Command', 'Source']),
                     table(tables['agent_activity.csv'], ['TimestampUtc', 'Agent', 'User', 'Actor', 'Tool', 'Detail', 'Cwd']))
        with open(os.path.join(out, 'report.html'), 'w', encoding='utf-8') as fh:
            fh.write(doc)


def live_roots():
    homes = []
    if os.name == 'nt':
        base = os.path.join(os.environ.get('SystemDrive', 'C:') + os.sep, 'Users')
        homes = [os.path.join(base, d) for d in os.listdir(base) if d not in ('Public', 'Default', 'Default User', 'All Users')]
        appdata = ['AppData/Roaming/Cursor/User', 'AppData/Roaming/Code/User', 'AppData/Roaming/Windsurf/User',
                   'AppData/Roaming/Antigravity/User', 'AppData/Roaming/Claude']
    else:
        for base in ('/Users', '/home'):
            if os.path.isdir(base):
                homes += [os.path.join(base, d) for d in os.listdir(base)]
        homes.append('/root')
        sup = 'Library/Application Support' if sys.platform == 'darwin' else '.config'
        appdata = [sup + '/Cursor/User', sup + '/Code/User', sup + '/Windsurf/User', sup + '/Antigravity/User', sup + '/Claude']
    roots = []
    for h in homes:
        for d in ['.claude', '.codex', '.cursor', '.copilot', '.gemini', '.codeium', '.cline'] + appdata:
            p = os.path.join(h, d)
            if os.path.isdir(p):
                roots.append(p)
        for f in ('.claude.json',):
            if os.path.isfile(os.path.join(h, f)):
                roots.append(os.path.join(h, f))
    return homes, roots


def main():
    ap = argparse.ArgumentParser(description='Agent Triage Kit offline analyzer (thelocalh0st.com)')
    ap.add_argument('evidence', nargs='?', help='ZIP, tar.gz or folder from a collector (KAPE/Velociraptor output folders work too)')
    ap.add_argument('-o', '--out', default='agent_triage_report', help='output folder (default: ./agent_triage_report)')
    ap.add_argument('--live', action='store_true', help='analyze this machine in place (read-only)')
    ap.add_argument('--project-depth', type=int, default=6, help='live mode: how deep to look for repo-level agent files')
    a = ap.parse_args()
    t = Triage()
    tmp = None
    if a.live:
        homes, roots = live_roots()
        for r in roots:
            if os.path.isfile(r):
                norm = r.replace('\\', '/')
                t.files.append({'path': r, 'norm': norm, 'agent': 'Claude Code', 'kind': 'claude-global', 'user': user_of(norm)})
            else:
                t.classify(r)
        skip = {'AppData', 'Library', 'node_modules', '.git', '.venv', 'venv', '__pycache__', '.cache', '.npm', '.cargo', '.rustup',
                '.claude', '.codex', '.cursor', '.copilot', '.gemini', '.codeium', '.vscode-server', '.Trash'}
        names = re.compile(r'^(\.mcp\.json|claude\.md|claude\.local\.md|agents\.md|gemini\.md|\.cursorrules|\.windsurfrules|\.clinerules|'
                           r'copilot-instructions\.md|skill\.md|.+\.mdc|.+\.instructions\.md|mcp\.json|settings\.json|settings\.local\.json|hooks\.json|config\.toml)$', re.I)
        for h in homes:
            base_depth = h.rstrip(os.sep).count(os.sep)
            for dirpath, dirs, files in os.walk(h):
                dirs[:] = [d for d in dirs if d not in skip and not os.path.islink(os.path.join(dirpath, d))]
                if dirpath.count(os.sep) - base_depth >= a.project_depth:
                    dirs[:] = []
                for n in files:
                    if names.match(n):
                        p = os.path.join(dirpath, n)
                        norm = p.replace('\\', '/')
                        for rx, agent, kind in RULES:
                            if rx.search(norm):
                                agent = agent or next((x for hh, x in AGENT_HINTS if hh in norm.lower()), 'Project files')
                                t.files.append({'path': p, 'norm': norm, 'agent': agent, 'kind': kind, 'user': user_of(norm)})
                                break
    elif a.evidence:
        src = a.evidence
        if os.path.isfile(src):
            # extract only the files the analyzers read, to short names (long paths break on Windows)
            tmp = tempfile.mkdtemp(prefix='atk_')
            n = 0
            if zipfile.is_zipfile(src):
                with zipfile.ZipFile(src) as z:
                    for m in z.infolist():
                        name = '/' + m.filename.replace('\\', '/').lstrip('/')
                        if m.is_dir() or '/../' in name or not t.match(name):
                            continue
                        n += 1
                        dst = os.path.join(tmp, '%06d%s' % (n, os.path.splitext(name)[1][:12]))
                        with z.open(m) as r, open(dst, 'wb') as w:
                            w.write(r.read())
                        stamp = dt.datetime(*m.date_time).timestamp()
                        os.utime(dst, (stamp, stamp))
                        t.add_file(dst, name)
            else:
                with tarfile.open(src) as tf:
                    for m in tf:
                        name = '/' + m.name.lstrip('/')
                        if not m.isfile() or '/../' in name or not t.match(name):
                            continue
                        n += 1
                        dst = os.path.join(tmp, '%06d%s' % (n, os.path.splitext(name)[1][:12]))
                        with tf.extractfile(m) as r, open(dst, 'wb') as w:
                            w.write(r.read())
                        os.utime(dst, (m.mtime, m.mtime))
                        t.add_file(dst, name)
        else:
            t.classify(src)
    else:
        ap.print_help()
        return 2
    print('  Agent Triage Kit analyzer | %d artifact files' % len(t.files))
    t.run()
    s = t.write(a.out)
    f = s['findings']
    print('  Findings   High %d   Medium %d   Low %d   Info %d' % (f['High'], f['Medium'], f['Low'], f['Info']))
    for x in [x for x in t.findings if x['Severity'] != 'Info'][:15]:
        print('    [%-6s] %-20s %s' % (x['Severity'], x['Agent'][:20], clip(x['Finding'], 90)))
    print('  MCP servers %d | hooks %d | activity rows %d' % (s['mcpServers'], s['hooks'], s['activityRows']))
    print('  Report: %s' % os.path.join(os.path.abspath(a.out), 'report.html'))
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())

ATK_PY_EOF
  python3 -I "$PYF" "$ARCHIVE" -o "$CASEDIR/report" | sed 's/^/  /'
  rm -f "$PYF"
else
  say "python3 not available: copy the archive to an analysis box and run"
  say "  python3 agent_triage_analyze.py $CASE.tar.gz -o report/"
fi
rm -f "$LIST" "$META"
say ""
say "Report   $CASEDIR/report"
say "Archive  $ARCHIVE"
say "SHA256   $($SHA "$ARCHIVE" | cut -d' ' -f1)"

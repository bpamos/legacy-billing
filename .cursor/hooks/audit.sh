#!/usr/bin/env bash
# Audit hook — append one JSONL line per tool/shell event (transcript-visible in cloud).
set -euo pipefail
input=$(cat)
ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
kind=$(printf '%s' "$input" | sed -n 's/.*"hook_event_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
name=$(printf '%s' "$input" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
if [ -z "$name" ]; then
  name=$(printf '%s' "$input" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1 | cut -c1-120)
fi
agent_id=$(printf '%s' "$input" | sed -n 's/.*"conversation_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
run_id=$(printf '%s' "$input" | sed -n 's/.*"generation_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
request_id=$(printf '%s' "$input" | sed -n 's/.*"request_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
args_summary=$(printf '%s' "$input" | tr '\n' ' ' | cut -c1-200)
json_escape() { printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])' 2>/dev/null || printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
line=$(printf '{"ts":"%s","agentId":"%s","runId":"%s","requestId":"%s","kind":"%s","name":"%s","argsSummary":"%s"}' \
  "$ts" "$(json_escape "${agent_id:-}")" "$(json_escape "${run_id:-}")" "$(json_escape "${request_id:-}")" \
  "$(json_escape "${kind:-unknown}")" "$(json_escape "${name:-}")" "$(json_escape "$args_summary")")
outdir="${CURSOR_PROJECT_DIR:-.}"
mkdir -p "$outdir/.cursor" 2>/dev/null || true
printf '%s\n' "$line" >> "$outdir/.cursor/audit.jsonl" 2>/dev/null || true
printf '%s\n' "$line" >&2
case "${kind:-}" in
  beforeShellExecution|beforeMCPExecution|beforeReadFile|preToolUse)
    printf '{"permission":"allow"}\n'
    ;;
esac
exit 0

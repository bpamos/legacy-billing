#!/usr/bin/env bash
# Guard hook — blocks dangerous shell/network and .env reads. Structured denial for Chapter 3.
set -euo pipefail
input=$(cat)

deny() {
  local msg="$1"
  python3 -c 'import json,sys; print(json.dumps({"permission":"deny","userMessage":sys.argv[1],"agentMessage":sys.argv[1]}))' "$msg"
  exit 0
}

allow() {
  printf '{"permission":"allow"}\n'
  exit 0
}

hook_event=$(printf '%s' "$input" | sed -n 's/.*"hook_event_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
command=$(printf '%s' "$input" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
file_path=$(printf '%s' "$input" | sed -n 's/.*"file_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
if [ -z "$file_path" ]; then
  file_path=$(printf '%s' "$input" | sed -n 's/.*"path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
fi

base=$(basename "$file_path" 2>/dev/null || true)
case "$base" in
  .env|.env.*|app.env)
    deny "GUARD DENIAL: reading credential files (.env*) is blocked by the repo guard hook."
    ;;
esac

if [ "$hook_event" = "beforeReadFile" ]; then
  allow
fi

if [ -n "$command" ]; then
  if printf '%s' "$command" | grep -Eq 'rm[[:space:]]+(-[a-zA-Z]*rf|-rf|-fr).*(\.\./|[[:space:]]/)'; then
    deny "GUARD DENIAL: rm -rf targeting paths outside the repository is blocked."
  fi
  if printf '%s' "$command" | grep -Eq '(^|[[:space:];|&])(curl|wget)[[:space:]]'; then
    if ! printf '%s' "$command" | grep -Eq 'registry\.npmjs\.org|api\.osv\.dev'; then
      deny "GUARD DENIAL: network fetch via curl/wget is limited to registry.npmjs.org and api.osv.dev."
    fi
  fi
fi

allow

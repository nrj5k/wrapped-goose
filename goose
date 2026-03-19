#!/usr/bin/env bash

set -euo pipefail

# Detect script directory
if command -v readlink >/dev/null 2>&1 && readlink -f "$0" >/dev/null 2>&1; then
  SCRIPT_PATH="$(readlink -f "$0")"
elif command -v python3 >/dev/null 2>&1; then
  SCRIPT_PATH="$(python3 -c "import os; print(os.path.realpath('$0'))")"
else
  echo "ERROR: Cannot resolve script path" >&2
  exit 1
fi

SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
if [[ ! "$SCRIPT_DIR" = /* ]]; then
  SCRIPT_DIR="$(cd "$SCRIPT_DIR" && pwd)"
fi

PROJECT_DIR="$(pwd)"
GOOSE_CONFIG="$HOME/.config/goose"
GOOSE_SHARE="${HOME}/.local/share/goose"
GOOSE_STATE="${HOME}/.local/state/goose"
UV_CACHE="${HOME}/.cache/uv"
UVX_LOCAL="${HOME}/.local/uvx"
UV_PYTHON="${HOME}/.local/share/uv/python"
NPM_LOCAL="${HOME}/.npm/"

# Whitelist of environment variables to pass through
ENV_VARS=(
  # API Keys
  OPENAI_API_KEY
  ANTHROPIC_API_KEY
  GOOSE_API_KEY
  GEMINI_API_KEY
  COHERE_API_KEY

  # SSH/Git
  SSH_AUTH_SOCK
  SSH_AGENT_LAUNCHER
  GIT_AUTHOR_NAME
  GIT_AUTHOR_EMAIL
  GIT_COMMITTER_NAME
  GIT_COMMITTER_EMAIL

  # User/Session
  USER
  LOGNAME
  HOME
  SHELL
  TERM
  COLORTERM
  LANG
  LC_ALL

  # XDG
  XDG_CONFIG_HOME
  XDG_CACHE_HOME
  XDG_DATA_HOME
  XDG_RUNTIME_DIR

  # Editor
  EDITOR
  VISUAL

  # Development
  GOPATH
  GOROOT
  NODE_PATH
  PYTHONPATH
  JAVA_HOME
  CARGO_HOME
)

# NOTE: CUSTOM READONLY PATH
EXTRA_PATH=${EXTRA_PATH:-""}
# NOTE: CUSTOM WRITABLE PATH
EXTRA_WPATH=${EXTRA_WPATH:-""}

# Build env args
ENV_ARGS=()
for var in "${ENV_VARS[@]}"; do
  if [[ -n "${!var:-}" ]]; then
    ENV_ARGS+=(--setenv "$var" "${!var}")
  fi
done

# Network isolation flag
GOOSE_ISOLATE_NETWORK=${GOOSE_ISOLATE_NETWORK:-""}
NETWORK_FLAGS=()

# Verify bwrap and goose exist
if ! command -v bwrap >/dev/null 2>&1; then
  echo "ERROR: bubblewrap not installed" >&2
  exit 1
fi

EXTRA_PATH_BWRAP=()
# NOTE: Process EXTRA_PATH as colon-separated list like PATH
if [[ -n $EXTRA_PATH ]]; then
  IFS=':' read -ra LPATHS <<<"$EXTRA_PATH"
  for path in "${LPATHS[@]}"; do
    if [[ -n "$path" && -e "$path" ]]; then
      EXTRA_PATH_BWRAP+=("--ro-bind" "$path" "$path")
    fi
  done
fi

EXTRA_WPATH_BWRAP=()
# NOTE:  Process EXTRA_WPATH as colon-separated list like PATH
if [[ -n $EXTRA_WPATH ]]; then
  IFS=':' read -ra LPATHS <<<"$EXTRA_WPATH"
  for path in "${LPATHS[@]}"; do
    if [[ -n "$path" && -e "$path" ]]; then
      EXTRA_WPATH_BWRAP+=("--bind" "$path" "$path")
    fi
  done
fi

if ! command -v goose >/dev/null 2>&1; then
  echo "ERROR: goose not found" >&2
  exit 1
fi

echo "Starting Goose in sandbox..."
echo "   Project: $PROJECT_DIR"
echo "   Config: $GOOSE_CONFIG"
echo "   Extra PATH: $EXTRA_PATH"

if [[ -n "$GOOSE_ISOLATE_NETWORK" ]]; then
  echo "   Network: ISOLATED"
  NETWORK_FLAGS+=(--unshare-all)
fi
exec bwrap \
  "${NETWORK_FLAGS[@]}" \
  --new-session \
  --die-with-parent \
  --clearenv \
  --setenv PATH "/usr/local/bin:/usr/bin:/bin" \
  --setenv HOME "$HOME" \
  --setenv TERM "${TERM:-xterm-256color}" \
  --setenv LANG "${LANG:-en_US.UTF-8}" \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --bind "$GOOSE_CONFIG" "$GOOSE_CONFIG" \
  --bind "$GOOSE_SHARE" "$GOOSE_SHARE" \
  --bind "$GOOSE_STATE" "$GOOSE_STATE" \
  --bind "${UV_CACHE}" "${UV_CACHE}" \
  --bind "${UVX_LOCAL}" "${UVX_LOCAL}" \
  --ro-bind "${UV_PYTHON}" "${UV_PYTHON}" \
  --bind "${NPM_LOCAL}" "${NPM_LOCAL}" \
  --ro-bind "$SCRIPT_DIR" "$SCRIPT_DIR" \
  "${ENV_ARGS[@]}" \
  "${EXTRA_PATH_BWRAP[@]}" \
  "${EXTRA_WPATH_BWRAP[@]}" \
  --ro-bind /usr /usr \
  --ro-bind /bin /bin \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /etc /etc \
  --bind "$PROJECT_DIR" "$PROJECT_DIR" \
  --chdir "$PROJECT_DIR" \
  /usr/bin/goose "$@"

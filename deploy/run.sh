#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAYBOOK_DIR="$ROOT_DIR/deploy/ansible"
PLAYBOOK="$PLAYBOOK_DIR/site.yml"

HOST=""
SSH_KEY=""
SSH_USER="${SSH_USER:-root}"
VARS_FILE="${VARS_FILE:-$PLAYBOOK_DIR/group_vars/all.yml}"
SECRETS_FILE="${SECRETS_FILE:-$PLAYBOOK_DIR/group_vars/all.secrets.yml}"
EXTRA_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  ./deploy/run.sh --host <ip-or-hostname> --ssh-key <path> [--ssh-user <user>] [--vars-file <path>] [--secrets-file <path>] [-- <extra ansible args>]

Examples:
  ./deploy/run.sh --host 203.0.113.10 --ssh-key ~/.ssh/id_ed25519
  ./deploy/run.sh --host panel.example.com --ssh-key ~/.ssh/id_ed25519 --ssh-user ubuntu -- --check
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      HOST="${2:-}"
      shift 2
      ;;
    --ssh-key)
      SSH_KEY="${2:-}"
      shift 2
      ;;
    --ssh-user)
      SSH_USER="${2:-}"
      shift 2
      ;;
    --vars-file)
      VARS_FILE="${2:-}"
      shift 2
      ;;
    --secrets-file)
      SECRETS_FILE="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$HOST" || -z "$SSH_KEY" ]]; then
  usage
  exit 1
fi

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "ansible-playbook is required" >&2
  exit 1
fi

if [[ ! -f "$SSH_KEY" ]]; then
  echo "SSH key not found: $SSH_KEY" >&2
  exit 1
fi

CMD=(
  ansible-playbook
  "$PLAYBOOK"
  -i "${HOST},"
  -u "$SSH_USER"
  --private-key "$SSH_KEY"
)

if [[ -f "$SECRETS_FILE" ]]; then
  CMD+=(-e "@$SECRETS_FILE")
else
  echo "warning: secrets file not found: $SECRETS_FILE" >&2
fi

if [[ -f "$VARS_FILE" ]]; then
  CMD+=(-e "@$VARS_FILE")
else
  echo "warning: vars file not found: $VARS_FILE" >&2
fi

CMD+=("${EXTRA_ARGS[@]}")

exec "${CMD[@]}"

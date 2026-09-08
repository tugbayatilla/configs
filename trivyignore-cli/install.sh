#!/usr/bin/env bash
#
# Install the `trivyignore` CLI.
#
#   ./install.sh              install (or upgrade) from this checkout
#   ./install.sh --dev        set up a local .venv for development instead
#   ./install.sh --uninstall  remove the installed tool
#
# Prefers `uv tool install`. Falls back to `pipx`, then `pip --user`.
# Installs uv automatically when none of those are available.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_NAME="trivyignore-cli"
BIN_NAME="trivyignore"

MODE="install"
FORCE_BACKEND=""

usage() {
  sed -n '3,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  --dev             create ./.venv with dev dependencies, do not install globally
  --uninstall       remove the installed tool
  --backend NAME    force a backend: uv | pipx | pip
  -h, --help        show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev) MODE="dev" ;;
    --uninstall) MODE="uninstall" ;;
    --backend)
      [[ $# -ge 2 ]] || { echo "error: --backend needs a value" >&2; exit 2; }
      FORCE_BACKEND="$2"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

# --- output helpers ---------------------------------------------------------

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_STEP=$'\033[1;34m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'; C_OFF=$'\033[0m'
else
  C_STEP=""; C_WARN=""; C_ERR=""; C_OFF=""
fi

step() { printf '%s==>%s %s\n' "$C_STEP" "$C_OFF" "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%sWARN:%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
die()  { printf '%sERROR:%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# uv installs here; it may not be on PATH yet in this shell.
export PATH="$HOME/.local/bin:$PATH"

# --- sanity -----------------------------------------------------------------

[[ -f "${SRC_DIR}/pyproject.toml" ]] \
  || die "pyproject.toml not found in ${SRC_DIR}; run this script from its own directory"

# --- backend selection ------------------------------------------------------

install_uv() {
  step "Installing uv"
  if have curl; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
  elif have wget; then
    wget -qO- https://astral.sh/uv/install.sh | sh
  else
    die "need curl or wget to install uv; install one, or use --backend pipx|pip"
  fi
  have uv || die "uv installed but not found on PATH; open a new shell and retry"
}

pick_backend() {
  if [[ -n "$FORCE_BACKEND" ]]; then
    case "$FORCE_BACKEND" in
      uv | pipx | pip) ;;
      *) die "unknown backend: ${FORCE_BACKEND} (expected uv, pipx or pip)" ;;
    esac
    if [[ "$FORCE_BACKEND" == "uv" ]] && ! have uv; then
      install_uv
    fi
    have "$FORCE_BACKEND" || die "${FORCE_BACKEND} not found on PATH"
    echo "$FORCE_BACKEND"
    return
  fi

  if have uv; then echo uv; return; fi
  if have pipx; then echo pipx; return; fi
  install_uv
  echo uv
}

# --- dev mode ---------------------------------------------------------------

if [[ "$MODE" == "dev" ]]; then
  have uv || install_uv
  step "Creating development environment in ${SRC_DIR}/.venv"
  (cd "$SRC_DIR" && uv sync --extra dev)
  info "run tests:  cd ${SRC_DIR} && uv run pytest"
  info "run cli:    cd ${SRC_DIR} && uv run ${BIN_NAME} --help"
  exit 0
fi

BACKEND="$(pick_backend)"

# --- uninstall --------------------------------------------------------------

if [[ "$MODE" == "uninstall" ]]; then
  step "Uninstalling ${PKG_NAME} (${BACKEND})"
  case "$BACKEND" in
    uv) uv tool uninstall "$PKG_NAME" ;;
    pipx) pipx uninstall "$PKG_NAME" ;;
    pip) "${PYTHON:-python3}" -m pip uninstall -y "$PKG_NAME" ;;
  esac
  step "Done."
  exit 0
fi

# --- install ----------------------------------------------------------------

step "Installing ${PKG_NAME} from ${SRC_DIR} (${BACKEND})"
case "$BACKEND" in
  uv)   uv tool install --force "$SRC_DIR" ;;
  pipx) pipx install --force "$SRC_DIR" ;;
  pip)  "${PYTHON:-python3}" -m pip install --user --upgrade "$SRC_DIR" ;;
esac

# --- verify -----------------------------------------------------------------

hash -r 2>/dev/null || true

if have "$BIN_NAME"; then
  step "Installed: $(command -v "$BIN_NAME")"
  "$BIN_NAME" --version || true
else
  warn "${BIN_NAME} is installed but not on your PATH."
  case "$BACKEND" in
    uv) info 'fix: uv tool update-shell   (then open a new shell)' ;;
    pipx) info 'fix: pipx ensurepath        (then open a new shell)' ;;
    pip) info 'fix: add "$(python3 -m site --user-base)/bin" to your PATH' ;;
  esac
fi

# --- runtime dependency check ----------------------------------------------

missing=()
have docker || missing+=("docker")
have trivy || missing+=("trivy")
if ((${#missing[@]})); then
  warn "not found on PATH: ${missing[*]}"
  info "${BIN_NAME} needs both to build and scan images"
  info "docker: https://docs.docker.com/get-docker/"
  info "trivy:  https://trivy.dev/latest/getting-started/installation/"
fi

step "Done. Try: ${BIN_NAME} --list"

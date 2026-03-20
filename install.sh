#!/bin/bash
# Ghost Tracker — One-click installer for macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/mhsn1/ghost-resource-tracker/main/install.sh | bash

set -e

REPO="mhsn1/ghost-resource-tracker"
INSTALL_DIR="$HOME/.ghost-tracker"
PYTHON_MIN="3.10"

echo ""
echo "👻  Ghost Resource Tracker — Installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Check Python ─────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "❌  Python 3 not found."
    echo "    Install from: https://www.python.org/downloads/"
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✅  Python $PY_VERSION found"

# ── Clone or update ───────────────────────────────────────────────────────────
if [ -d "$INSTALL_DIR" ]; then
    echo "📦  Updating existing installation..."
    cd "$INSTALL_DIR" && git pull --quiet
else
    echo "📦  Installing to $INSTALL_DIR ..."
    git clone --quiet "https://github.com/$REPO.git" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# ── Virtual environment ───────────────────────────────────────────────────────
if [ ! -d "$INSTALL_DIR/.venv" ]; then
    python3 -m venv "$INSTALL_DIR/.venv"
fi

source "$INSTALL_DIR/.venv/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet psutil rich

# ── Shell alias ───────────────────────────────────────────────────────────────
SHELL_RC="$HOME/.zshrc"
[ -f "$HOME/.bashrc" ] && SHELL_RC="$HOME/.bashrc"

ALIAS_LINE="alias ghost-tracker='source $INSTALL_DIR/.venv/bin/activate && python -m ghost_tracker.cli'"

if ! grep -q "ghost-tracker" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# Ghost Resource Tracker" >> "$SHELL_RC"
    echo "$ALIAS_LINE" >> "$SHELL_RC"
    echo "✅  Added 'ghost-tracker' command to $SHELL_RC"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅  Installation complete!"
echo ""
echo "   Run now:    source $SHELL_RC && ghost-tracker"
echo "   Next time:  ghost-tracker"
echo ""

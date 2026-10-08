#!/usr/bin/env bash
#
# One-step installer for Behind The Cloud (Kali / Debian / Ubuntu / macOS).
# After this you can run `behindthecloud <domain>` from anywhere.
#
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREEN='\033[32m'; YELLOW='\033[33m'; CYAN='\033[36m'; RESET='\033[0m'
say() { printf "${CYAN}[*]${RESET} %s\n" "$1"; }
ok()  { printf "${GREEN}[+]${RESET} %s\n" "$1"; }
warn(){ printf "${YELLOW}[!]${RESET} %s\n" "$1"; }

say "Installing Behind The Cloud (by Wasim Patel)..."

# 1) Best path: pipx (isolated install, auto-adds to PATH).
if command -v pipx >/dev/null 2>&1; then
    pipx install --force "$DIR"
    pipx ensurepath >/dev/null 2>&1 || true
    ok "Installed with pipx."
    ok "Run:  behindthecloud example.com"
    exit 0
fi

# 2) Try a normal user pip install.
if python3 -m pip install --user "$DIR" >/dev/null 2>&1; then
    ok "Installed with pip (--user)."
# 3) Kali/Debian mark system Python as externally managed (PEP 668) -> use a venv.
else
    warn "System Python is externally managed; installing into a private venv..."
    VENV="$HOME/.local/share/behind-the-cloud-venv"
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --upgrade pip >/dev/null
    "$VENV/bin/pip" install "$DIR" >/dev/null
    mkdir -p "$HOME/.local/bin"
    ln -sf "$VENV/bin/behindthecloud" "$HOME/.local/bin/behindthecloud"
    ln -sf "$VENV/bin/btcloud"        "$HOME/.local/bin/btcloud"
    ok "Installed into $VENV and linked into ~/.local/bin"
fi

# Make sure ~/.local/bin is on PATH for this and future shells.
case ":$PATH:" in
    *":$HOME/.local/bin:"*) : ;;
    *)
        warn "~/.local/bin is not on your PATH. Adding it to your shell profile."
        for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
            [ -f "$rc" ] && ! grep -q '.local/bin' "$rc" \
                && echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
        done
        export PATH="$HOME/.local/bin:$PATH"
        warn "Open a new terminal (or run: source ~/.bashrc) if the command isn't found."
        ;;
esac

ok "Done. Run:  behindthecloud example.com"

# One-step installer for Behind The Cloud on Windows (PowerShell).
# After this you can run `behindthecloud <domain>` from any terminal.
#
#   Right-click > Run with PowerShell, or:   powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Say($m)  { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

# Find a Python launcher.
$py = $null
if (Get-Command py -ErrorAction SilentlyContinue)       { $py = "py" }
elseif (Get-Command python -ErrorAction SilentlyContinue){ $py = "python" }
if (-not $py) { Warn "Python not found. Install it from https://python.org (tick 'Add to PATH')."; exit 1 }

Say "Installing Behind The Cloud (by Wasim Patel)..."

# Best path: pipx (isolated, auto-manages PATH).
if (Get-Command pipx -ErrorAction SilentlyContinue) {
    pipx install --force $dir
    pipx ensurepath | Out-Null
    Ok "Installed with pipx. Open a NEW terminal, then run:  behindthecloud example.com"
    exit 0
}

Say "pipx not found; setting it up (recommended, isolated)..."
try {
    & $py -m pip install --user --quiet pipx
    & $py -m pipx install --force $dir
    & $py -m pipx ensurepath | Out-Null
    Ok "Installed with pipx. Open a NEW terminal, then run:  behindthecloud example.com"
    exit 0
} catch {
    Warn "pipx route failed; falling back to a plain pip --user install."
}

& $py -m pip install --user $dir
Ok "Installed with pip (--user)."
Warn "If 'behindthecloud' isn't found, either open a new terminal, or run it as:"
Warn "    $py -m behindthecloud example.com"

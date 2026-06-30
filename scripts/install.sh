#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Vulnara Installer for Kali Linux / Debian / Ubuntu
#
# Interactive installer that sets up Vulnara locally using a virtual
# environment, installs Python dependencies, and optionally installs
# external security tools through the system package manager (apt).
#
# Vulnara does not bundle or redistribute any external tools.
#
# Usage (from project root):
#   chmod +x scripts/install.sh
#   ./scripts/install.sh
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colours & helpers ────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

ok()    { echo -e "${GREEN}[OK]${RESET}    $1"; }
info()  { echo -e "${CYAN}[INFO]${RESET}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $1"; }
err()   { echo -e "${RED}[ERROR]${RESET} $1"; }

banner() {
    echo ""
    echo -e "${CYAN}  ╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}  ║                                                  ║${RESET}"
    echo -e "${CYAN}  ║         V U L N A R A   I N S T A L L E R        ║${RESET}"
    echo -e "${CYAN}  ║         Cross-Platform Setup Utility              ║${RESET}"
    echo -e "${CYAN}  ║                                                  ║${RESET}"
    echo -e "${CYAN}  ╚══════════════════════════════════════════════════╝${RESET}"
    echo ""
}

menu() {
    echo -e "  ${BOLD}[1] Basic install${RESET}"
    echo -e "  ${DIM}    Create/use venv, install requirements, run doctor${RESET}"
    echo ""
    echo -e "  ${BOLD}[2] Recommended install${RESET}"
    echo -e "  ${DIM}    Basic + run pytest, validate folders, git status${RESET}"
    echo ""
    echo -e "  ${BOLD}[3] Advanced install with optional external tools${RESET}"
    echo -e "  ${DIM}    Recommended + offer nmap, tshark, docker.io${RESET}"
    echo ""
    echo -e "  ${DIM}[Q] Quit${RESET}"
    echo ""
}

# ── Prerequisite detection ───────────────────────────────────────────────────

command_exists() {
    command -v "$1" &>/dev/null
}

assert_python() {
    # Try python3 first, then python
    if command_exists python3; then
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_CMD="python"
    else
        err "Python 3 is not installed or not on PATH."
        info "Install Python: sudo apt install python3 python3-venv python3-pip"
        return 1
    fi

    local ver
    ver=$($PYTHON_CMD --version 2>&1)
    ok "Python found: $ver"

    # Check that python3-venv module is available
    if ! $PYTHON_CMD -m venv --help &>/dev/null; then
        warn "python3-venv module may not be installed."
        info "Install it: sudo apt install python3-venv"
    fi

    return 0
}

assert_git() {
    if command_exists git; then
        local ver
        ver=$(git --version 2>&1)
        ok "Git found: $ver"
        return 0
    fi
    warn "Git is not installed or not on PATH."
    info "Some features (git status) will be skipped."
    return 1
}

assert_apt() {
    if command_exists apt; then
        ok "apt package manager found."
        return 0
    fi
    warn "apt is not available on this system."
    info "External tool installation requires apt (Debian/Ubuntu/Kali)."
    return 1
}

# ── Project root detection ───────────────────────────────────────────────────

detect_project_root() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Script is in scripts/ subdirectory
    local parent_dir
    parent_dir="$(dirname "$script_dir")"

    if [[ -f "$parent_dir/main.py" ]]; then
        PROJECT_ROOT="$parent_dir"
        return 0
    fi

    # Script is in project root
    if [[ -f "$script_dir/main.py" ]]; then
        PROJECT_ROOT="$script_dir"
        return 0
    fi

    # Fallback: current directory
    if [[ -f "./main.py" ]]; then
        PROJECT_ROOT="$(pwd)"
        return 0
    fi

    err "Cannot locate the Vulnara project root (main.py not found)."
    info "Please run this script from the Vulnara project directory."
    return 1
}

# ── Step: Virtual environment ────────────────────────────────────────────────

setup_venv() {
    local venv_path="$PROJECT_ROOT/venv"

    if [[ -f "$venv_path/bin/python" ]]; then
        ok "Virtual environment already exists at venv/"
    else
        info "Creating virtual environment..."
        $PYTHON_CMD -m venv "$venv_path"
        if [[ $? -ne 0 ]]; then
            err "Failed to create virtual environment."
            info "Try: sudo apt install python3-venv"
            return 1
        fi
        ok "Virtual environment created at venv/"
    fi

    VENV_PYTHON="$venv_path/bin/python"
    VENV_PIP="$venv_path/bin/pip"
    VENV_PYTEST="$venv_path/bin/pytest"
    return 0
}

# ── Step: Install requirements ───────────────────────────────────────────────

install_requirements() {
    local req_file="$PROJECT_ROOT/requirements.txt"

    if [[ ! -f "$req_file" ]]; then
        err "requirements.txt not found at $req_file"
        return 1
    fi

    info "Installing Python dependencies..."
    "$VENV_PIP" install -r "$req_file" --quiet 2>&1 | tail -n 3
    if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
        warn "pip install may have had issues. Retrying with verbose output..."
        "$VENV_PIP" install -r "$req_file"
        if [[ $? -ne 0 ]]; then
            err "Failed to install requirements."
            return 1
        fi
    fi
    ok "Python dependencies installed."
    return 0
}

# ── Step: Run doctor ─────────────────────────────────────────────────────────

run_doctor() {
    info "Running Vulnara doctor check..."
    "$VENV_PYTHON" "$PROJECT_ROOT/main.py" doctor
    if [[ $? -ne 0 ]]; then
        warn "Doctor command reported issues."
        return 1
    fi
    ok "Doctor check passed."
    return 0
}

# ── Step: Run pytest ─────────────────────────────────────────────────────────

run_pytest() {
    if [[ ! -f "$VENV_PYTEST" ]]; then
        warn "pytest not found in venv. Skipping test run."
        return 0
    fi
    info "Running test suite..."
    "$VENV_PYTEST"
    if [[ $? -ne 0 ]]; then
        warn "Some tests failed. Review the output above."
        return 1
    fi
    ok "All tests passed."
    return 0
}

# ── Step: Validate folders ───────────────────────────────────────────────────

validate_folders() {
    local folders=("storage" "output" "docs" "config" "src" "tests")
    local all_ok=true

    for folder in "${folders[@]}"; do
        local path="$PROJECT_ROOT/$folder"
        if [[ -d "$path" ]]; then
            ok "Folder exists: $folder/"
        else
            warn "Folder missing: $folder/"
            all_ok=false
        fi
    done

    $all_ok && return 0 || return 1
}

# ── Step: Git status ─────────────────────────────────────────────────────────

show_git_status() {
    if ! command_exists git; then
        warn "Git not found. Skipping git status."
        return 0
    fi
    info "Git status:"
    cd "$PROJECT_ROOT" && git status --short
    ok "Git status displayed."
    return 0
}

# ── Step: External tools (Advanced) ──────────────────────────────────────────

EXTERNAL_TOOLS=(
    "nmap:nmap:Network port scanner"
    "tshark:tshark:Network protocol analyzer (Wireshark CLI)"
    "docker:docker.io:Container runtime"
)

check_external_tool() {
    local cmd="$1"
    command_exists "$cmd"
}

show_external_tool_status() {
    echo ""
    info "External tool status:"
    for entry in "${EXTERNAL_TOOLS[@]}"; do
        IFS=':' read -r cmd pkg desc <<< "$entry"
        if check_external_tool "$cmd"; then
            ok "$cmd — installed ($desc)"
        else
            warn "$cmd — not found ($desc)"
        fi
    done
    echo ""
}

install_external_tools() {
    echo ""
    echo -e "${YELLOW}  ┌──────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}  │  IMPORTANT NOTICE                                           │${RESET}"
    echo -e "${YELLOW}  │                                                              │${RESET}"
    echo -e "${YELLOW}  │  Vulnara does not bundle or redistribute external tools.     │${RESET}"
    echo -e "${YELLOW}  │  Tools are installed from your OS package manager (apt).     │${RESET}"
    echo -e "${YELLOW}  │  Admin/sudo permission, restart, or license acceptance may   │${RESET}"
    echo -e "${YELLOW}  │  be required by the individual tool installers.              │${RESET}"
    echo -e "${YELLOW}  └──────────────────────────────────────────────────────────────┘${RESET}"
    echo ""

    if ! assert_apt; then
        err "Cannot install external tools without apt."
        return 1
    fi

    show_external_tool_status

    echo -n "Do you want to install missing external tools? (y/N): "
    read -r answer
    if [[ "$answer" != "y" && "$answer" != "Y" && "$answer" != "yes" ]]; then
        info "Skipping external tool installation."
        return 0
    fi

    for entry in "${EXTERNAL_TOOLS[@]}"; do
        IFS=':' read -r cmd pkg desc <<< "$entry"

        if check_external_tool "$cmd"; then
            ok "$cmd is already installed. Skipping."
            continue
        fi

        echo -n "Install $cmd ($desc) via apt? (y/N): "
        read -r confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" && "$confirm" != "yes" ]]; then
            info "Skipping $cmd."
            continue
        fi

        info "Installing $pkg via apt..."
        if sudo apt install -y "$pkg"; then
            ok "$cmd installation completed."
        else
            warn "apt install for $pkg returned an error."
            info "You may need to install $cmd manually."
        fi
    done

    echo ""
    info "Re-checking external tool status after installation..."
    show_external_tool_status
}

# ── Install modes ────────────────────────────────────────────────────────────

basic_install() {
    echo ""
    echo -e "${CYAN}━━━ Basic Install ━━━${RESET}"
    echo ""

    setup_venv         || return 1
    install_requirements || return 1
    run_doctor         || true

    echo ""
    ok "Basic install completed."
    return 0
}

recommended_install() {
    basic_install || return 1

    echo ""
    echo -e "${CYAN}━━━ Recommended Install (additional steps) ━━━${RESET}"
    echo ""

    run_pytest       || true
    validate_folders || true
    show_git_status  || true

    echo ""
    ok "Recommended install completed."
    echo ""
    echo -e "  ${GREEN}✔ Vulnara is ready for development and contribution.${RESET}"
    echo -e "  ${GREEN}✔ Run scans with: venv/bin/python main.py scan <url> -d <domain>${RESET}"
    echo -e "  ${GREEN}✔ Run tests with: venv/bin/pytest${RESET}"
    echo ""
    return 0
}

advanced_install() {
    recommended_install || return 1

    echo ""
    echo -e "${CYAN}━━━ Advanced Install (optional external tools) ━━━${RESET}"
    echo ""

    install_external_tools

    echo ""
    ok "Advanced install completed."
    return 0
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    banner

    # Prerequisite: Python
    assert_python || exit 1
    assert_git || true

    # Locate project root
    detect_project_root || exit 1
    ok "Project root: $PROJECT_ROOT"
    echo ""

    menu

    echo -n "Select an option [1/2/3/Q]: "
    read -r choice

    case "$choice" in
        1) basic_install ;;
        2) recommended_install ;;
        3) advanced_install ;;
        [Qq])
            info "Exiting installer."
            exit 0
            ;;
        *)
            err "Invalid selection: '$choice'. Please run the installer again."
            exit 1
            ;;
    esac

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    ok "Vulnara installer finished."
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

main

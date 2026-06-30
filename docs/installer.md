# Installer Guide

Vulnara ships with cross-platform installer scripts that automate local setup. The installers are interactive, menu-driven, and never perform silent operations on your system.

## Quick Start

### Windows (PowerShell)

```powershell
git clone https://github.com/chanuka8/Vulnara.git
cd Vulnara
.\scripts\install.ps1
```

If PowerShell blocks execution, run this first:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

### Kali Linux / Debian / Ubuntu

```bash
git clone https://github.com/chanuka8/Vulnara.git
cd Vulnara
chmod +x scripts/install.sh
./scripts/install.sh
```

## Installer Modes

The installer presents three options:

### [1] Basic Install

The minimum setup needed to run Vulnara.

- Creates a Python virtual environment (`venv/`)
- Installs all Python dependencies from `requirements.txt`
- Runs `python main.py doctor` to validate the project

This is sufficient for running scans immediately.

### [2] Recommended Install

Everything in Basic, plus contributor-readiness checks.

- Runs the full test suite (`pytest`)
- Validates that required project folders exist (`storage/`, `output/`, `docs/`, `config/`, `src/`, `tests/`)
- Runs `git status` to show the repository state
- Displays a contributor-ready confirmation message

This is the recommended choice for developers and contributors.

### [3] Advanced Install with Optional External Tools

Everything in Recommended, plus the option to install external security tools from your OS package manager.

Before offering any installations, the installer displays this notice:

> Vulnara does not bundle or redistribute external tools.
> Tools are installed from your OS package manager.
> Admin/sudo permission, restart, or license acceptance may be required.

The installer then:

1. Shows the current status of each external tool (installed or not found)
2. Asks for confirmation before proceeding
3. For each missing tool, asks individually whether to install it
4. Re-checks tool status after installation

**Windows tools** (installed via `winget`):

| Tool | winget ID | Description |
| ------ | ----------- | ------------- |
| nmap | `Insecure.Nmap` | Network port scanner |
| Wireshark | `WiresharkFoundation.Wireshark` | Network protocol analyzer (includes tshark) |
| Docker | `Docker.DockerDesktop` | Container runtime |

**Linux/Kali tools** (installed via `apt`):

| Tool | apt package | Description |
| ------ | ------------- | ------------- |
| nmap | `nmap` | Network port scanner |
| tshark | `tshark` | Network protocol analyzer (Wireshark CLI) |
| Docker | `docker.io` | Container runtime |

## Prerequisites

The installer automatically detects and reports on these prerequisites:

| Prerequisite | Required | Notes |
| -------------- | ---------- | ------- |
| Python 3.11+ | Yes | Must be on PATH |
| Git | No | Used for `git status` only |
| winget (Windows) | No | Required only for external tool installation |
| apt (Linux) | No | Required only for external tool installation |

If Python is not found, the installer exits immediately with a helpful message. If Git or the package manager is missing, non-critical features are skipped gracefully.

## Output Style

The installer uses consistent message prefixes:

- `[OK]` â€” Step completed successfully (green)
- `[INFO]` â€” Informational message (cyan)
- `[WARN]` â€” Non-fatal warning (yellow)
- `[ERROR]` â€” Fatal error (red)

## Vulnara Without External Tools

Vulnara is fully functional without any external tools installed. The core scanning pipeline (HTTP probe, header analysis, robots.txt, sitemap, cookie security) uses only Python libraries and does not depend on nmap, tshark, Docker, or any other external binary.

External tools are offered as optional enhancements for users who want extended capabilities in their security assessment workflow.

## Troubleshooting

### PowerShell execution policy error

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

### Python venv module not found (Linux)

```bash
sudo apt install python3-venv
```

### pip install fails

Ensure you have internet connectivity and try upgrading pip:

```bash
venv/bin/pip install --upgrade pip
```

### winget not found (Windows)

winget is included with Windows 10 version 1709 and later. Update your Windows installation or install the App Installer from the Microsoft Store.

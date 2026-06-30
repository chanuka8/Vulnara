# Vulnara

Vulnara is a local-first terminal security assessment automation tool for authorized testing environments.

It automates scope validation, reconnaissance, safe vulnerability checks, evidence collection, finding classification, and professional report generation.

## Current Version

0.1.0

## Project Type

Vulnara is a Pentest Workflow Automation Tool and Authorized Security Assessment Automation Tool.

It is not an exploit automation framework.

## Safety Policy

Vulnara does not perform:

- Automatic exploitation
- Brute force attacks
- Password spraying
- Payload generation
- Stealth scanning
- Bypass techniques
- Unauthorized scanning

## Installation

### Quick Start (Recommended)

**Windows (PowerShell):**

```powershell
git clone https://github.com/chanuka8/Vulnara.git
cd Vulnara
.\scripts\install.ps1
```

**Kali Linux / Debian / Ubuntu:**

```bash
git clone https://github.com/chanuka8/Vulnara.git
cd Vulnara
chmod +x scripts/install.sh
./scripts/install.sh
```

The installer presents three options: Basic, Recommended, and Advanced. See [docs/installer.md](docs/installer.md) for details.

### Manual Installation

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
python main.py doctor
```

## Python Support

Vulnara is designed to support Python 3.11, 3.12, 3.13, and 3.14.

## License

License will be finalized before the first public release.

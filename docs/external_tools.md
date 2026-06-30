# External Tools

Vulnara is a standalone Python tool that does not require any external binaries to function. However, certain external tools can extend your security assessment workflow when used alongside Vulnara.

## Important Policy

- **Vulnara does not bundle, redistribute, or automatically install any external tools.**
- External tools are only installed when you explicitly choose the Advanced install option and confirm each tool individually.
- Tools are installed through your operating system's official package manager (`winget` on Windows, `apt` on Kali/Debian/Ubuntu).
- Each tool has its own license, system requirements, and permissions model.

## Supported External Tools

### nmap

| Property | Details |
| ---------- | --------- |
| Description | Network port and service scanner |
| Website | [https://nmap.org](https://nmap.org) |
| License | Nmap Public Source License (NPSL) |
| Windows install | `winget install Insecure.Nmap` |
| Linux install | `sudo apt install nmap` |
| Used for | Port scanning, service fingerprinting, host discovery |

### Wireshark / tshark

| Property | Details |
| ---------- | --------- |
| Description | Network protocol analyzer |
| Website | [https://www.wireshark.org](https://www.wireshark.org) |
| License | GNU GPL v2 |
| Windows install | `winget install WiresharkFoundation.Wireshark` |
| Linux install | `sudo apt install tshark` |
| Used for | Packet capture and network traffic analysis |

**Note:** On Windows, the installer offers Wireshark which includes the `tshark` command-line tool. On Linux, only the `tshark` CLI is installed.

### Docker

| Property | Details |
| ---------- | --------- |
| Description | Container runtime |
| Website | [https://www.docker.com](https://www.docker.com) |
| License | Apache License 2.0 |
| Windows install | `winget install Docker.DockerDesktop` |
| Linux install | `sudo apt install docker.io` |
| Used for | Running containerized scanning environments |

**Note:** Docker Desktop on Windows may require a restart, Hyper-V or WSL2 configuration, and acceptance of the Docker Subscription Service Agreement. On Linux, you may need to add your user to the `docker` group.

## Using Vulnara Without External Tools

Vulnara's core pipeline is fully functional without any external tools:

| Feature | External tool required? |
| --------- | ------------------------ |
| HTTP probing | No |
| Security header analysis | No |
| robots.txt parsing | No |
| sitemap.xml parsing | No |
| Cookie security analysis | No |
| Finding generation | No |
| Evidence collection | No |
| HTML report generation | No |
| AI-assisted analysis | No (uses HTTP API) |

All core scanning, analysis, and reporting features use built-in Python libraries (`httpx`, `beautifulsoup4`, `jinja2`, etc.).

## Manual Installation

If you prefer to install external tools manually instead of using the Vulnara installer:

### Windows

```powershell
# nmap
winget install Insecure.Nmap

# Wireshark (includes tshark)
winget install WiresharkFoundation.Wireshark

# Docker Desktop
winget install Docker.DockerDesktop
```

### Kali Linux / Debian / Ubuntu

```bash
# nmap
sudo apt install nmap

# tshark (Wireshark CLI)
sudo apt install tshark

# Docker
sudo apt install docker.io
```

## Verifying Installation

After installation, verify that tools are available on your PATH:

```bash
nmap --version
tshark --version
docker --version
```

On Windows, you may need to restart your terminal or add the tool's installation directory to your PATH environment variable.

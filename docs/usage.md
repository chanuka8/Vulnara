# Usage Guide

Vulnara is operated from the terminal.

## Show Help

```powershell
python main.py --help
```

## Doctor Command

```powershell
python main.py doctor
```

## Version Command

```powershell
python main.py version
```

## Scan Command

Basic syntax:

```powershell
python main.py scan <target-url> --authorized-domain <authorized-domain> --profile <profile-name>
```

Example:

```powershell
python main.py scan https://example.com --authorized-domain example.com --profile passive_recon
```

## Authorization Scope

Every scan requires an authorized domain.

Allowed examples:

```powershell
python main.py scan https://example.com --authorized-domain example.com
python main.py scan https://app.example.com --authorized-domain example.com
```

Out-of-scope targets are blocked by scope validation.

## Available Profiles

### passive_recon

Runs HTTP probe, security header analysis, robots.txt check, sitemap.xml check, findings generation, evidence storage, and HTML report generation.

### headers_only

Runs HTTP probe, security header analysis, findings generation, evidence storage, and HTML report generation.

## Evidence Output

Each scan creates JSON evidence under:

```text
storage/evidence/<hostname>/<scan_id>/
```

## Report Output

Each scan creates an HTML report under:

```text
output/reports/<hostname>/<scan_id>/report.html
```

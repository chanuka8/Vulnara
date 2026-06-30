# Scan Profiles

Vulnara uses scan profiles to control which modules run during a scan.

Scan profiles are configured in:

```text
config/scan_profiles.yaml
```

## Purpose

Profiles make scan behavior explicit and predictable.

They help avoid accidental module execution and keep assessments controlled.

## Current Profiles

### passive_recon

The passive_recon profile runs the full current safe assessment workflow.

Enabled modules:

- HTTP probe
- Security header analysis
- robots.txt passive check
- sitemap.xml passive check
- Findings generation
- Evidence storage
- HTML report generation

Command:

```powershell
python main.py scan https://example.com --authorized-domain example.com --profile passive_recon
```

### headers_only

The headers_only profile runs a smaller workflow focused on HTTP reachability and security headers.

Enabled modules:

- HTTP probe
- Security header analysis
- Findings generation
- Evidence storage
- HTML report generation

Disabled modules:

- robots.txt check
- sitemap.xml check

Command:

```powershell
python main.py scan https://example.com --authorized-domain example.com --profile headers_only
```

## Disabled Module Behavior

When a module is disabled by a profile, Vulnara records the skipped state in evidence output.

This keeps reports consistent and makes it clear which modules were intentionally not executed.

## Adding New Profiles

New profiles should be added only when they keep the project safe and predictable.

Future profiles should avoid:

- Exploit execution
- Brute force behavior
- Credential attacks
- Stealth behavior
- Destructive checks

## Recommended Rule

Every new module should be explicitly enabled or disabled in each scan profile.

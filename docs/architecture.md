# Architecture Overview

Vulnara uses a small, modular terminal-first architecture.

The goal is to keep the project easy to understand, safe to extend, and suitable for authorized security assessment workflows.

## High-Level Flow

```text
CLI Command
  -> Configuration Loader
  -> Scope Validator
  -> Scan Orchestrator
  -> Recon Modules
  -> Finding Rule Engine
  -> Evidence Store
  -> Report Generator
```

## Main Components

### CLI Layer

The CLI entry point receives user commands and displays terminal output.

Main files:

- main.py
- src/vulnara/app.py

### Configuration Layer

Configuration files control runtime behavior and scan profiles.

Main files:

- config/settings.yaml
- config/scan_profiles.yaml
- src/vulnara/core/config_loader.py

### Scope Validation

Scope validation confirms that the requested target belongs to the authorized domain.

Main file:

- src/vulnara/core/scope.py

### Scan Orchestrator

The orchestrator coordinates the full scan workflow.

Main file:

- src/vulnara/core/orchestrator.py

### Recon Modules

Recon modules collect safe, non-destructive assessment data.

Current modules:

- HTTP probe
- Security headers
- robots.txt passive reconnaissance
- sitemap.xml passive reconnaissance

Main folder:

- src/vulnara/modules/recon/

### Finding Engine

The finding engine converts normalized scan data into structured findings.

Main files:

- src/vulnara/findings/rules.py
- src/vulnara/models/finding.py

### Evidence Store

The evidence store saves structured JSON evidence for every scan.

Main file:

- src/vulnara/core/evidence.py

### Report Generator

The report generator creates local HTML reports from scan results.

Main files:

- src/vulnara/reports/generator.py
- src/vulnara/reports/templates/report.html

## Design Principles

- Authorized use only
- Local-first operation
- Safe by default
- No automatic exploitation
- No credential attacks
- No stealth behavior
- Evidence-focused output
- Clear module boundaries
- Simple terminal workflow

## Output Model

Each scan creates:

- JSON evidence files
- A summary file
- An HTML report

Generated artifacts are stored locally and ignored by Git.

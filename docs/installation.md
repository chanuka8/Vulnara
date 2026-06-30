# Installation Guide

This guide explains how to install and run Vulnara locally on Windows.

## Requirements

- Python 3.11 or newer
- Git
- PowerShell
- Internet connection for installing dependencies

## Clone the Repository

```powershell
git clone https://github.com/chanuka8/Vulnara.git
cd Vulnara
```

## Create a Virtual Environment

```powershell
python -m venv venv
```

## Activate the Virtual Environment

```powershell
venv\Scripts\activate
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
venv\Scripts\activate
```

## Install Dependencies

```powershell
pip install -r requirements.txt
```

## Verify Installation

```powershell
pytest
python main.py doctor
```

## Run a Test Scan

```powershell
python main.py scan https://example.com --authorized-domain example.com --profile passive_recon
```

## Output Folders

- Evidence: storage/evidence/
- Reports: output/reports/

Generated evidence and report files are ignored by Git.

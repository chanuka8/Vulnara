<#
.SYNOPSIS
    Vulnara Installer for Windows.
.DESCRIPTION
    Interactive installer that sets up Vulnara locally using a virtual
    environment, installs Python dependencies, and optionally installs
    external security tools through the Windows package manager (winget).

    Vulnara does not bundle or redistribute any external tools.
.NOTES
    Run from the Vulnara project root:
        .\scripts\install.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# -- Colours and helpers -------------------------------------------------------

function Write-Ok    { param([string]$Msg) Write-Host "[OK]    $Msg" -ForegroundColor Green }
function Write-Info  { param([string]$Msg) Write-Host "[INFO]  $Msg" -ForegroundColor Cyan }
function Write-Warn  { param([string]$Msg) Write-Host "[WARN]  $Msg" -ForegroundColor Yellow }
function Write-Err   { param([string]$Msg) Write-Host "[ERROR] $Msg" -ForegroundColor Red }

function Write-Banner {
    Write-Host ""
    Write-Host "  +====================================================+" -ForegroundColor Cyan
    Write-Host "  ||                                                  ||" -ForegroundColor Cyan
    Write-Host "  ||         V U L N A R A   I N S T A L L E R        ||" -ForegroundColor Cyan
    Write-Host "  ||         Cross-Platform Setup Utility              ||" -ForegroundColor Cyan
    Write-Host "  ||                                                  ||" -ForegroundColor Cyan
    Write-Host "  +====================================================+" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Menu {
    Write-Host "  [1] Basic install" -ForegroundColor White
    Write-Host "      Create/use venv, install requirements, run doctor" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [2] Recommended install" -ForegroundColor White
    Write-Host "      Basic + run pytest, validate folders, git status" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [3] Advanced install with optional external tools" -ForegroundColor White
    Write-Host "      Recommended + offer nmap, Wireshark/tshark, Docker" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [Q] Quit" -ForegroundColor DarkGray
    Write-Host ""
}

# -- Prerequisite detection ----------------------------------------------------

function Test-Command {
    param([string]$Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Assert-Python {
    if (Test-Command "python") {
        $ver = & python --version 2>&1
        Write-Ok "Python found: $ver"
        return $true
    }
    Write-Err "Python is not installed or not on PATH."
    Write-Info "Download Python from https://www.python.org/downloads/"
    return $false
}

function Assert-Git {
    if (Test-Command "git") {
        $ver = & git --version 2>&1
        Write-Ok "Git found: $ver"
        return $true
    }
    Write-Warn "Git is not installed or not on PATH."
    Write-Info "Some features (git status) will be skipped."
    return $false
}

function Assert-Winget {
    if (Test-Command "winget") {
        Write-Ok "winget package manager found."
        return $true
    }
    Write-Warn "winget is not available on this system."
    Write-Info "External tool installation requires winget (Windows 10 1709+)."
    return $false
}

# -- Project root detection ----------------------------------------------------

function Get-ProjectRoot {
    $scriptDir = Split-Path -Parent $PSScriptRoot
    # If invoked from scripts/ go up one level; otherwise use CWD
    if (Test-Path (Join-Path $scriptDir "main.py")) {
        return $scriptDir
    }
    # PSScriptRoot IS the project root (scripts/ is child)
    if (Test-Path (Join-Path $PSScriptRoot "main.py")) {
        return $PSScriptRoot
    }
    # Fallback: the script is inside scripts/, go one level up
    $parent = Split-Path -Parent $PSScriptRoot
    if (Test-Path (Join-Path $parent "main.py")) {
        return $parent
    }
    # Last resort: current directory
    if (Test-Path (Join-Path (Get-Location) "main.py")) {
        return (Get-Location).Path
    }
    Write-Err "Cannot locate the Vulnara project root (main.py not found)."
    Write-Info "Please run this script from the Vulnara project directory."
    return $null
}

# -- Step: Virtual environment -------------------------------------------------

function Install-Venv {
    param([string]$Root)
    $venvPath = Join-Path $Root "venv"
    if (Test-Path (Join-Path $venvPath "Scripts\python.exe")) {
        Write-Ok 'Virtual environment already exists at venv/'
    } else {
        Write-Info "Creating virtual environment..."
        & python -m venv $venvPath
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to create virtual environment."
            return $false
        }
        Write-Ok 'Virtual environment created at venv/'
    }
    return $true
}

function Get-VenvPython {
    param([string]$Root)
    return Join-Path $Root "venv\Scripts\python.exe"
}

function Get-VenvPip {
    param([string]$Root)
    return Join-Path $Root "venv\Scripts\pip.exe"
}

# -- Step: Install requirements ------------------------------------------------

function Install-Requirements {
    param([string]$Root)
    $pip = Get-VenvPip $Root
    $reqFile = Join-Path $Root "requirements.txt"
    if (-not (Test-Path $reqFile)) {
        Write-Err "requirements.txt not found at $reqFile"
        return $false
    }
    Write-Info "Installing Python dependencies..."
    & $pip install -r $reqFile --quiet 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "pip install returned a non-zero exit code. Retrying with verbose output..."
        & $pip install -r $reqFile
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to install requirements."
            return $false
        }
    }
    Write-Ok "Python dependencies installed."
    return $true
}

# -- Step: Run doctor ----------------------------------------------------------

function Invoke-Doctor {
    param([string]$Root)
    $py = Get-VenvPython $Root
    Write-Info "Running Vulnara doctor check..."
    & $py (Join-Path $Root "main.py") doctor
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Doctor command reported issues."
        return $false
    }
    Write-Ok "Doctor check passed."
    return $true
}

# -- Step: Run pytest ----------------------------------------------------------

function Invoke-Pytest {
    param([string]$Root)
    $pytest = Join-Path $Root "venv\Scripts\pytest.exe"
    if (-not (Test-Path $pytest)) {
        Write-Warn "pytest not found in venv. Skipping test run."
        return $true
    }
    Write-Info "Running test suite..."
    & $pytest
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Some tests failed. Review the output above."
        return $false
    }
    Write-Ok "All tests passed."
    return $true
}

# -- Step: Validate folders ----------------------------------------------------

function Confirm-Folders {
    param([string]$Root)
    $folders = @("storage", "output", "docs", "config", "src", "tests")
    $allOk = $true
    foreach ($folder in $folders) {
        $path = Join-Path $Root $folder
        if (Test-Path $path) {
            Write-Ok "Folder exists: $folder/"
        } else {
            Write-Warn "Folder missing: $folder/"
            $allOk = $false
        }
    }
    return $allOk
}

# -- Step: Git status ----------------------------------------------------------

function Show-GitStatus {
    param([string]$Root)
    if (-not (Test-Command "git")) {
        Write-Warn "Git not found. Skipping git status."
        return
    }
    Write-Info "Git status:"
    Push-Location $Root
    & git status --short
    Pop-Location
    Write-Ok "Git status displayed."
}

# -- Step: External tools (Advanced) -------------------------------------------

$ExternalTools = @(
    @{ Name = "nmap";      WingetId = "Insecure.Nmap";          Description = "Network port scanner" },
    @{ Name = "wireshark"; WingetId = "WiresharkFoundation.Wireshark"; Description = "Network protocol analyzer (includes tshark)" },
    @{ Name = "docker";    WingetId = "Docker.DockerDesktop";   Description = "Container runtime" }
)

function Test-ExternalTool {
    param([string]$Name)
    switch ($Name) {
        "nmap"      { return Test-Command "nmap" }
        "wireshark" { return (Test-Command "tshark") -or (Test-Command "wireshark") }
        "docker"    { return Test-Command "docker" }
        default     { return $false }
    }
}

function Show-ExternalToolStatus {
    Write-Host ""
    Write-Info "External tool status:"
    foreach ($tool in $ExternalTools) {
        if (Test-ExternalTool $tool.Name) {
            Write-Ok "$($tool.Name) -- installed ($($tool.Description))"
        } else {
            Write-Warn "$($tool.Name) -- not found ($($tool.Description))"
        }
    }
    Write-Host ""
}

function Install-ExternalTools {
    # Warnings
    Write-Host ""
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "  |  IMPORTANT NOTICE                                            |" -ForegroundColor Yellow
    Write-Host "  |                                                              |" -ForegroundColor Yellow
    Write-Host "  |  Vulnara does not bundle or redistribute external tools.     |" -ForegroundColor Yellow
    Write-Host "  |  Tools are installed from your OS package manager (winget).  |" -ForegroundColor Yellow
    Write-Host "  |  Admin permission, restart, or license acceptance may be     |" -ForegroundColor Yellow
    Write-Host "  |  required by the individual tool installers.                 |" -ForegroundColor Yellow
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host ""

    if (-not (Assert-Winget)) {
        Write-Err "Cannot install external tools without winget."
        return
    }

    Show-ExternalToolStatus

    $answer = Read-Host "Do you want to install missing external tools? (y/N)"
    if ($answer -notin @("y", "Y", "yes", "Yes", "YES")) {
        Write-Info "Skipping external tool installation."
        return
    }

    foreach ($tool in $ExternalTools) {
        if (Test-ExternalTool $tool.Name) {
            Write-Ok "$($tool.Name) is already installed. Skipping."
            continue
        }

        $confirm = Read-Host "Install $($tool.Name) ($($tool.Description)) via winget? (y/N)"
        if ($confirm -notin @("y", "Y", "yes", "Yes", "YES")) {
            Write-Info "Skipping $($tool.Name)."
            continue
        }

        Write-Info "Installing $($tool.Name) via winget..."
        & winget install --id $tool.WingetId --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "winget install for $($tool.Name) returned a non-zero exit code."
            Write-Info "You may need to install $($tool.Name) manually or restart your terminal."
        } else {
            Write-Ok "$($tool.Name) installation completed."
        }
    }

    Write-Host ""
    Write-Info "Re-checking external tool status after installation..."
    Show-ExternalToolStatus
}

# -- Install modes -------------------------------------------------------------

function Invoke-BasicInstall {
    param([string]$Root)
    Write-Host ""
    Write-Host "--- Basic Install ---" -ForegroundColor Cyan
    Write-Host ""

    if (-not (Install-Venv $Root))         { return $false }
    if (-not (Install-Requirements $Root)) { return $false }
    Invoke-Doctor $Root | Out-Null

    Write-Host ""
    Write-Ok "Basic install completed."
    return $true
}

function Invoke-RecommendedInstall {
    param([string]$Root)

    if (-not (Invoke-BasicInstall $Root)) { return $false }

    Write-Host ""
    Write-Host "--- Recommended Install (additional steps) ---" -ForegroundColor Cyan
    Write-Host ""

    Invoke-Pytest $Root | Out-Null
    Confirm-Folders $Root | Out-Null
    Show-GitStatus $Root

    Write-Host ""
    Write-Ok "Recommended install completed."
    Write-Host ""
    Write-Host "  [OK] Vulnara is ready for development and contribution." -ForegroundColor Green
    Write-Host "  [OK] Run scans with: venv\Scripts\python main.py scan [url] -d [domain]" -ForegroundColor Green
    Write-Host "  [OK] Run tests with: venv\Scripts\pytest" -ForegroundColor Green
    Write-Host ""
    return $true
}

function Invoke-AdvancedInstall {
    param([string]$Root)

    if (-not (Invoke-RecommendedInstall $Root)) { return $false }

    Write-Host ""
    Write-Host "--- Advanced Install (optional external tools) ---" -ForegroundColor Cyan
    Write-Host ""

    Install-ExternalTools

    Write-Host ""
    Write-Ok "Advanced install completed."
    return $true
}

# -- Main ----------------------------------------------------------------------

function Main {
    Write-Banner

    # Prerequisite: Python
    if (-not (Assert-Python)) {
        Write-Err "Python is required. Exiting."
        exit 1
    }
    Assert-Git | Out-Null

    # Locate project root
    $root = Get-ProjectRoot
    if (-not $root) { exit 1 }
    Write-Ok "Project root: $root"
    Write-Host ""

    Write-Menu

    $choice = Read-Host "Select an option [1/2/3/Q]"

    switch ($choice) {
        "1" { Invoke-BasicInstall $root | Out-Null }
        "2" { Invoke-RecommendedInstall $root | Out-Null }
        "3" { Invoke-AdvancedInstall $root | Out-Null }
        { $_ -in @("Q", "q") } {
            Write-Info "Exiting installer."
            exit 0
        }
        default {
            Write-Err "Invalid selection: '$choice'. Please run the installer again."
            exit 1
        }
    }

    Write-Host ""
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Ok "Vulnara installer finished."
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host ""
}

Main

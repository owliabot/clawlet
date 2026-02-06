#Requires -Version 5.1
<#
.SYNOPSIS
    Clawlet Installation Script for Windows

.DESCRIPTION
    Installs Clawlet from source on Windows systems.
    Requires Rust toolchain (will guide installation if missing).

.PARAMETER Prefix
    Installation prefix directory. Defaults to $env:USERPROFILE\.cargo\bin

.PARAMETER Help
    Show this help message

.EXAMPLE
    .\install.ps1
    
.EXAMPLE
    .\install.ps1 -Prefix "C:\tools"

.LINK
    https://github.com/owliabot/clawlet
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Prefix = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$Help
)

# === Configuration ===
$RepoUrl = "https://github.com/owliabot/clawlet.git"
$ConfigDir = Join-Path $env:USERPROFILE ".clawlet"

# === Colors ===
function Write-Info {
    param([string]$Message)
    Write-Host "ℹ " -ForegroundColor Blue -NoNewline
    Write-Host $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Err {
    param([string]$Message)
    Write-Host "✗ " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Show-Help {
    Get-Help $MyInvocation.PSCommandPath -Detailed
    exit 0
}

function Test-Command {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

function Ensure-Git {
    if (-not (Test-Command "git")) {
        Write-Err "git is required but not installed."
        Write-Host ""
        Write-Host "Install git from: https://git-scm.com/download/win"
        Write-Host "Or via winget:    winget install Git.Git"
        exit 1
    }
}

function Ensure-Rust {
    if (Test-Command "cargo") {
        $version = & cargo --version 2>&1
        Write-Success "Rust toolchain found: $version"
        return
    }

    Write-Warn "Rust toolchain not found"
    Write-Host ""
    Write-Host "Please install Rust from: https://rustup.rs"
    Write-Host ""
    Write-Host "  1. Download and run rustup-init.exe from https://rustup.rs"
    Write-Host "  2. Follow the installation prompts"
    Write-Host "  3. Restart your terminal"
    Write-Host "  4. Re-run this installation script"
    Write-Host ""
    exit 1
}

function Build-FromSource {
    $tempDir = Join-Path $env:TEMP "clawlet-install-$(Get-Random)"
    
    try {
        Write-Info "Cloning clawlet repository..."
        & git clone --depth 1 $RepoUrl $tempDir 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to clone repository"
        }

        Write-Info "Building clawlet (this may take a few minutes)..."
        Push-Location $tempDir
        try {
            & cargo build --release --package clawlet-cli 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Build failed"
            }
        }
        finally {
            Pop-Location
        }

        $binaryPath = Join-Path $tempDir "target\release\clawlet.exe"
        if (-not (Test-Path $binaryPath)) {
            $binaryPath = Join-Path $tempDir "target\release\clawlet-cli.exe"
            if (-not (Test-Path $binaryPath)) {
                throw "Binary not found after build"
            }
        }

        return @{
            BinaryPath = $binaryPath
            TempDir = $tempDir
        }
    }
    catch {
        if (Test-Path $tempDir) {
            Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Install-Binary {
    param(
        [string]$BinaryPath,
        [string]$DestDir
    )

    $dest = Join-Path $DestDir "clawlet.exe"
    
    Write-Info "Installing to $dest..."

    if (-not (Test-Path $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
    }

    Copy-Item -Path $BinaryPath -Destination $dest -Force
    Write-Success "Binary installed to $dest"
    
    return $DestDir
}

function Create-ConfigDir {
    Write-Info "Creating configuration directory at $ConfigDir..."

    $keysDir = Join-Path $ConfigDir "keys"
    $logsDir = Join-Path $ConfigDir "logs"
    
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    New-Item -ItemType Directory -Path $keysDir -Force | Out-Null
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

    $policyFile = Join-Path $ConfigDir "policy.yaml"
    if (-not (Test-Path $policyFile)) {
        $policyContent = @"
# Clawlet Policy Configuration
# See: https://github.com/owliabot/clawlet/blob/main/config/policy.example.yaml

version: 1

# Daily spending limits (in USD equivalent)
limits:
  daily_usd: 100.0

# Allowed token addresses (leave empty to allow all)
allowed_tokens: []

# Recipient whitelist (leave empty to allow all)
allowed_recipients: []

# Require human confirmation above this amount
confirm_above_usd: 50.0
"@
        Set-Content -Path $policyFile -Value $policyContent
        Write-Success "Created default policy at $policyFile"
    }
    else {
        Write-Warn "Policy file already exists, skipping"
    }

    Write-Success "Configuration directory ready"
}

function Show-PostInstall {
    param([string]$BinDir)

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║          Clawlet installed successfully! 🐾              ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    # Check if bin dir is in PATH
    $pathDirs = $env:PATH -split ';'
    if ($pathDirs -notcontains $BinDir) {
        Write-Warn "NOTE: $BinDir is not in your PATH"
        Write-Host ""
        Write-Host "    Add it to your PATH permanently:"
        Write-Host ""
        Write-Host "    [Environment]::SetEnvironmentVariable('PATH', `$env:PATH + ';$BinDir', 'User')" -ForegroundColor Cyan
        Write-Host ""
    }

    Write-Host "  Next steps:"
    Write-Host ""
    Write-Host "    1. " -NoNewline
    Write-Host "Initialize clawlet:"
    Write-Host "       clawlet init" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    2. " -NoNewline
    Write-Host "Start the RPC server:"
    Write-Host "       clawlet serve" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    3. " -NoNewline
    Write-Host "Configure your policy:"
    Write-Host "       $ConfigDir\policy.yaml" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  For help, run: clawlet --help"
    Write-Host "  Documentation: https://github.com/owliabot/clawlet"
    Write-Host ""
}

# === Main ===
function Main {
    if ($Help) {
        Show-Help
    }

    Write-Host ""
    Write-Host "Clawlet Installer" -ForegroundColor White
    Write-Host "================="
    Write-Host ""

    Write-Info "Detected: Windows ($env:PROCESSOR_ARCHITECTURE)"

    Ensure-Git
    Ensure-Rust

    # Determine install location
    if ([string]::IsNullOrEmpty($Prefix)) {
        $binDir = Join-Path $env:USERPROFILE ".cargo\bin"
    }
    else {
        $binDir = Join-Path $Prefix "bin"
    }

    $buildResult = Build-FromSource
    
    try {
        $installedDir = Install-Binary -BinaryPath $buildResult.BinaryPath -DestDir $binDir
        Create-ConfigDir
        Show-PostInstall -BinDir $installedDir
    }
    finally {
        # Cleanup temp directory
        if (Test-Path $buildResult.TempDir) {
            Remove-Item -Recurse -Force $buildResult.TempDir -ErrorAction SilentlyContinue
        }
    }
}

# Run main
try {
    Main
}
catch {
    Write-Err $_.Exception.Message
    exit 1
}

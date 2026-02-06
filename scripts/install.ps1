#Requires -Version 5.1
<#
.SYNOPSIS
    Clawlet Installation Script for Windows

.DESCRIPTION
    Installs Clawlet on Windows systems.
    Downloads pre-built binary from GitHub Releases, or builds from source as fallback.

.PARAMETER Prefix
    Installation prefix directory. Defaults to $env:USERPROFILE\.cargo\bin

.PARAMETER Version
    Specific version to install (e.g., v0.1.0). Defaults to latest.

.PARAMETER FromSource
    Build from source instead of downloading pre-built binary.

.PARAMETER Help
    Show this help message

.EXAMPLE
    .\install.ps1
    
.EXAMPLE
    .\install.ps1 -Version v0.1.0

.EXAMPLE
    .\install.ps1 -Prefix "C:\tools"

.EXAMPLE
    .\install.ps1 -FromSource

.LINK
    https://github.com/owliabot/clawlet
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Prefix = "",
    
    [Parameter(Mandatory = $false)]
    [string]$Version = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$FromSource,
    
    [Parameter(Mandatory = $false)]
    [switch]$Help
)

# === Configuration ===
$GitHubRepo = "owliabot/clawlet"
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

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "x86_64" }
        "ARM64" { return "aarch64" }
        default { throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
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

function Get-LatestVersion {
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/latest" -ErrorAction Stop
        return $response.tag_name
    }
    catch {
        return $null
    }
}

function Download-Release {
    param(
        [string]$Arch,
        [string]$Ver,
        [string]$TempDir
    )

    # Expected asset name: clawlet-<version>-<arch>-windows.zip
    $assetName = "clawlet-$Ver-$Arch-windows.zip"
    $downloadUrl = "https://github.com/$GitHubRepo/releases/download/$Ver/$assetName"
    
    Write-Info "Downloading $assetName..."
    
    $archivePath = Join-Path $TempDir $assetName
    
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -ErrorAction Stop
    }
    catch {
        return $null
    }

    Write-Info "Extracting..."
    Expand-Archive -Path $archivePath -DestinationPath $TempDir -Force

    # Find the binary
    $binaryPath = Join-Path $TempDir "clawlet.exe"
    if (-not (Test-Path $binaryPath)) {
        $binaryPath = Get-ChildItem -Path $TempDir -Filter "clawlet.exe" -Recurse | Select-Object -First 1 -ExpandProperty FullName
        if (-not $binaryPath) {
            return $null
        }
    }

    return $binaryPath
}

function Build-FromSource {
    param([string]$TempDir)
    
    Ensure-Git
    Ensure-Rust

    $repoDir = Join-Path $TempDir "clawlet-src"

    Write-Info "Cloning clawlet repository..."
    & git clone --depth 1 "https://github.com/$GitHubRepo.git" $repoDir 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to clone repository"
    }

    Write-Info "Building clawlet (this may take a few minutes)..."
    Push-Location $repoDir
    try {
        & cargo build --release --package clawlet-cli 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed"
        }
    }
    finally {
        Pop-Location
    }

    $binaryPath = Join-Path $repoDir "target\release\clawlet.exe"
    if (-not (Test-Path $binaryPath)) {
        $binaryPath = Join-Path $repoDir "target\release\clawlet-cli.exe"
        if (-not (Test-Path $binaryPath)) {
            throw "Binary not found after build"
        }
    }

    return $binaryPath
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
    param(
        [string]$BinDir,
        [string]$InstalledVersion
    )

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║          Clawlet installed successfully! 🐾              ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    if ($InstalledVersion) {
        Write-Host "  Version: " -NoNewline
        Write-Host $InstalledVersion -ForegroundColor White
        Write-Host ""
    }

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
    Write-Host "  Documentation: https://github.com/$GitHubRepo"
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

    $arch = Get-Arch
    Write-Info "Detected: Windows ($arch)"

    # Determine install location
    if ([string]::IsNullOrEmpty($Prefix)) {
        $binDir = Join-Path $env:USERPROFILE ".cargo\bin"
    }
    else {
        $binDir = Join-Path $Prefix "bin"
    }

    $tempDir = Join-Path $env:TEMP "clawlet-install-$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        $binaryPath = $null
        $installedVersion = ""

        if ($FromSource) {
            Write-Info "Building from source (-FromSource specified)..."
            $binaryPath = Build-FromSource -TempDir $tempDir
            $installedVersion = "(built from source)"
        }
        else {
            # Try to download pre-built binary
            if ([string]::IsNullOrEmpty($Version)) {
                Write-Info "Fetching latest release version..."
                $Version = Get-LatestVersion
            }

            if (-not $Version) {
                throw "No releases found. Use -FromSource to build manually, or check https://github.com/$GitHubRepo/releases"
            }

            Write-Info "Version: $Version"
            $binaryPath = Download-Release -Arch $arch -Ver $Version -TempDir $tempDir
            $installedVersion = $Version

            if (-not $binaryPath) {
                throw "No pre-built binary available for Windows/$arch (version: $Version). Use -FromSource to build manually."
            }
        }

        $installedDir = Install-Binary -BinaryPath $binaryPath -DestDir $binDir
        Create-ConfigDir
        Show-PostInstall -BinDir $installedDir -InstalledVersion $installedVersion
    }
    finally {
        # Cleanup temp directory
        if (Test-Path $tempDir) {
            Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
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

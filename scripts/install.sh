#!/usr/bin/env bash
#
# Clawlet Installation Script
# https://github.com/owliabot/clawlet
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/install.sh | bash
#   ./install.sh [OPTIONS]
#
# Options:
#   --prefix DIR       Install to DIR instead of /usr/local (default: /usr/local)
#   --version VER      Install specific version (default: latest)
#   --from-source      Build from source instead of downloading binary
#   --isolated         Install in isolated mode with dedicated clawlet user
#   --help             Show this help message
#

set -euo pipefail

# === Configuration ===
GITHUB_REPO="owliabot/clawlet"
DEFAULT_PREFIX="/usr/local"
CONFIG_DIR="$HOME/.clawlet"
CLAWLET_USER="clawlet"
CLAWLET_GROUP="clawlet"

# === Colors ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# === Helpers ===
info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1" >&2
}

die() {
    error "$1"
    exit 1
}

show_help() {
    cat << 'EOF'
Clawlet Installation Script

USAGE:
    install.sh [OPTIONS]

OPTIONS:
    --prefix DIR       Install to DIR/bin instead of /usr/local/bin
                       Binary will be placed at DIR/bin/clawlet
    --version VER      Install specific version (e.g., v0.1.0). Default: latest
    --from-source      Build from source instead of downloading binary
    --isolated         Install in isolated mode with dedicated 'clawlet' system user
                       - Creates clawlet system user for key isolation
                       - Sets up systemd (Linux) or launchd (macOS) service
                       - Configures secure file permissions (700)
    --help             Show this help message

EXAMPLES:
    # Install latest release binary (user mode)
    ./install.sh

    # Install in isolated mode (recommended for production)
    sudo ./install.sh --isolated

    # Install specific version
    ./install.sh --version v0.1.0

    # Install to custom prefix
    ./install.sh --prefix ~/.local

    # Build from source
    ./install.sh --from-source

    # Pipe from curl
    curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/install.sh | bash

    # Isolated mode via curl (requires sudo)
    curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/install.sh | sudo bash -s -- --isolated

EOF
    exit 0
}

# === Argument Parsing ===
PREFIX="$DEFAULT_PREFIX"
VERSION=""
FROM_SOURCE=false
ISOLATED=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --prefix)
            PREFIX="${2:-}"
            if [[ -z "$PREFIX" ]]; then
                die "--prefix requires a directory argument"
            fi
            shift 2
            ;;
        --version)
            VERSION="${2:-}"
            if [[ -z "$VERSION" ]]; then
                die "--version requires a version argument"
            fi
            shift 2
            ;;
        --from-source)
            FROM_SOURCE=true
            shift
            ;;
        --isolated)
            ISOLATED=true
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            die "Unknown option: $1 (use --help for usage)"
            ;;
    esac
done

BIN_DIR="$PREFIX/bin"

# === System Detection ===
detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        *)       die "Unsupported operating system: $os" ;;
    esac
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)   echo "x86_64" ;;
        aarch64|arm64)  echo "aarch64" ;;
        *)              die "Unsupported architecture: $arch" ;;
    esac
}

# === Dependency Checks ===
check_command() {
    command -v "$1" &> /dev/null
}

ensure_curl() {
    if ! check_command curl; then
        die "curl is required but not installed. Please install curl first."
    fi
}

ensure_git() {
    if ! check_command git; then
        die "git is required but not installed. Please install git first."
    fi
}

ensure_rust() {
    if check_command cargo; then
        local version
        version=$(cargo --version)
        success "Rust toolchain found: $version"
        return 0
    fi

    warn "Rust toolchain not found"
    info "Installing Rust via rustup..."

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

    # Source cargo env for current session
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env" 2>/dev/null || true

    if ! check_command cargo; then
        die "Rust installation failed. Please install manually: https://rustup.rs"
    fi

    success "Rust installed successfully"
}

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        die "Isolated mode requires root privileges. Please run with sudo."
    fi
}

# === Release Download ===
get_latest_version() {
    local version
    version=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' \
        | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [[ -z "$version" ]]; then
        return 1
    fi
    echo "$version"
}

download_release() {
    local os="$1"
    local arch="$2"
    local version="$3"
    local tmp_dir="$4"

    # Construct download URL
    # Expected asset name: clawlet-<version>-<arch>-<os>.tar.gz
    # e.g., clawlet-v0.1.0-x86_64-linux.tar.gz
    local asset_name="clawlet-${version}-${arch}-${os}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${asset_name}"

    # Use >&2 for info messages since stdout is captured by caller
    info "Downloading ${asset_name}..." >&2
    
    local archive_path="${tmp_dir}/${asset_name}"
    if ! curl -fsSL -o "$archive_path" "$download_url" 2>/dev/null; then
        return 1
    fi

    info "Extracting..." >&2
    tar -xzf "$archive_path" -C "$tmp_dir" || return 1

    # Find the binary
    local binary_path="${tmp_dir}/clawlet"
    if [[ ! -f "$binary_path" ]]; then
        # Try in subdirectory (use -perm +111 for macOS compatibility)
        binary_path=$(find "$tmp_dir" -name "clawlet" -type f | head -1)
        if [[ -z "$binary_path" || ! -f "$binary_path" ]]; then
            return 1
        fi
    fi

    echo "$binary_path"
}

# === Build from Source ===
build_from_source() {
    local tmp_dir="$1"

    ensure_git
    ensure_rust

    # Use >&2 for info messages since stdout is captured by caller
    info "Cloning clawlet repository..." >&2
    git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$tmp_dir/clawlet" || die "Failed to clone repository"

    info "Building clawlet (this may take a few minutes)..." >&2
    cd "$tmp_dir/clawlet"
    cargo build --release --package clawlet-cli || die "Build failed"

    local binary_path="$tmp_dir/clawlet/target/release/clawlet"
    if [[ ! -f "$binary_path" ]]; then
        # Try the crate name if different
        binary_path="$tmp_dir/clawlet/target/release/clawlet-cli"
        if [[ ! -f "$binary_path" ]]; then
            die "Binary not found after build"
        fi
    fi

    echo "$binary_path"
}

# === Installation ===
install_binary() {
    local binary_path="$1"
    local dest="$BIN_DIR/clawlet"

    info "Installing to $dest..."

    # Create bin directory if needed
    if [[ ! -d "$BIN_DIR" ]]; then
        if [[ "$PREFIX" == "$DEFAULT_PREFIX" ]]; then
            sudo mkdir -p "$BIN_DIR" || die "Failed to create $BIN_DIR (try running with sudo)"
        else
            mkdir -p "$BIN_DIR" || die "Failed to create $BIN_DIR"
        fi
    fi

    # Copy binary
    if [[ "$PREFIX" == "$DEFAULT_PREFIX" && ! -w "$BIN_DIR" ]]; then
        sudo cp "$binary_path" "$dest" || die "Failed to install binary"
        sudo chmod 755 "$dest"
    else
        cp "$binary_path" "$dest" || die "Failed to install binary"
        chmod 755 "$dest"
    fi

    success "Binary installed to $dest"
}

create_config_dir() {
    info "Creating configuration directory at $CONFIG_DIR..."
    mkdir -p "$CONFIG_DIR"/{keys,logs}
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR/keys"

    # Create default policy if it doesn't exist
    if [[ ! -f "$CONFIG_DIR/policy.yaml" ]]; then
        cat > "$CONFIG_DIR/policy.yaml" << 'POLICY'
# Clawlet Policy Configuration
# See: https://github.com/owliabot/clawlet/blob/main/config/policy.example.yaml

# Maximum total USD value of transfers per day
daily_transfer_limit_usd: 100.0

# Maximum USD value per single transfer
per_tx_limit_usd: 50.0

# Allowed token symbols or addresses (empty = all allowed)
allowed_tokens: []

# Allowed chain IDs (empty = all allowed)
allowed_chains: []

# Transfers above this USD value require human approval
require_approval_above_usd: 50.0
POLICY
        success "Created default policy at $CONFIG_DIR/policy.yaml"
    else
        warn "Policy file already exists, skipping"
    fi

    success "Configuration directory ready"
}

# === Isolated Mode Functions ===

# Create clawlet system user
create_clawlet_user_linux() {
    if id "$CLAWLET_USER" &>/dev/null; then
        info "User '$CLAWLET_USER' already exists"
        return 0
    fi

    info "Creating system user '$CLAWLET_USER'..."
    useradd \
        --system \
        --create-home \
        --home-dir "/home/$CLAWLET_USER" \
        --shell /usr/sbin/nologin \
        --comment "Clawlet Wallet Engine" \
        "$CLAWLET_USER" || die "Failed to create user"
    
    success "Created system user '$CLAWLET_USER'"
}

create_clawlet_user_macos() {
    if id "$CLAWLET_USER" &>/dev/null; then
        info "User '$CLAWLET_USER' already exists"
        return 0
    fi

    info "Creating system user '$CLAWLET_USER' on macOS..."

    # Find next available UID (system users typically < 500 on macOS)
    local next_uid=400
    while dscl . -read "/Users/_$next_uid" &>/dev/null 2>&1 || \
          dscl . -list /Users UniqueID | grep -q "\\b$next_uid\\b"; do
        ((next_uid++))
        if [[ $next_uid -ge 500 ]]; then
            die "Could not find available system UID"
        fi
    done

    # Create user via dscl
    dscl . -create "/Users/$CLAWLET_USER" || die "Failed to create user record"
    dscl . -create "/Users/$CLAWLET_USER" UserShell /usr/bin/false
    dscl . -create "/Users/$CLAWLET_USER" RealName "Clawlet Wallet Engine"
    dscl . -create "/Users/$CLAWLET_USER" UniqueID "$next_uid"
    dscl . -create "/Users/$CLAWLET_USER" PrimaryGroupID 20  # staff group
    dscl . -create "/Users/$CLAWLET_USER" NFSHomeDirectory "/Users/$CLAWLET_USER"
    dscl . -create "/Users/$CLAWLET_USER" IsHidden 1

    # Create home directory
    mkdir -p "/Users/$CLAWLET_USER"
    chown "$CLAWLET_USER:staff" "/Users/$CLAWLET_USER"
    chmod 700 "/Users/$CLAWLET_USER"

    success "Created system user '$CLAWLET_USER' (UID: $next_uid)"
}

create_clawlet_user() {
    local os="$1"
    case "$os" in
        linux)  create_clawlet_user_linux ;;
        darwin) create_clawlet_user_macos ;;
    esac
}

# Get home directory for clawlet user
get_clawlet_home() {
    local os="$1"
    case "$os" in
        linux)  echo "/home/$CLAWLET_USER" ;;
        darwin) echo "/Users/$CLAWLET_USER" ;;
    esac
}

# Create data directory for isolated mode
create_isolated_data_dir() {
    local clawlet_home="$1"
    local data_dir="$clawlet_home/.clawlet"

    info "Creating data directory at $data_dir..."
    mkdir -p "$data_dir"/{keystore,logs}
    
    # Create default config
    if [[ ! -f "$data_dir/config.yaml" ]]; then
        cat > "$data_dir/config.yaml" << 'CONFIG'
# Clawlet Configuration
# See: https://github.com/owliabot/clawlet/blob/main/docs/usage.md

# RPC server bind address (127.0.0.1 for local only)
bind_address: "127.0.0.1:9100"

# Chain RPC endpoints (add your own)
# chain_rpc_urls:
#   1: "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
#   8453: "https://mainnet.base.org"
CONFIG
        success "Created config at $data_dir/config.yaml"
    fi

    # Create default policy
    if [[ ! -f "$data_dir/policy.yaml" ]]; then
        cat > "$data_dir/policy.yaml" << 'POLICY'
# Clawlet Policy Configuration
# See: https://github.com/owliabot/clawlet/blob/main/config/policy.example.yaml

# Maximum total USD value of transfers per day
daily_transfer_limit_usd: 100.0

# Maximum USD value per single transfer
per_tx_limit_usd: 50.0

# Allowed token symbols or addresses (empty = all allowed)
allowed_tokens: []

# Allowed chain IDs (empty = all allowed)
allowed_chains: []

# Transfers above this USD value require human approval
require_approval_above_usd: 50.0
POLICY
        success "Created policy at $data_dir/policy.yaml"
    fi

    # Set secure permissions
    chown -R "$CLAWLET_USER:$(id -gn $CLAWLET_USER 2>/dev/null || echo staff)" "$data_dir"
    chmod 700 "$data_dir"
    chmod 700 "$data_dir/keystore"
    chmod 700 "$data_dir/logs"
    chmod 600 "$data_dir/config.yaml" 2>/dev/null || true
    chmod 600 "$data_dir/policy.yaml" 2>/dev/null || true

    success "Data directory ready with secure permissions (700)"
}

# Install systemd service (Linux)
install_systemd_service() {
    local clawlet_home="$1"
    local service_file="/etc/systemd/system/clawlet.service"

    info "Installing systemd service..."

    cat > "$service_file" << EOF
[Unit]
Description=Clawlet Wallet Engine
Documentation=https://github.com/owliabot/clawlet
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$CLAWLET_USER
Group=$CLAWLET_GROUP

# Environment
Environment=RUST_LOG=info
Environment=CLAWLET_HOME=$clawlet_home/.clawlet

# Execution
ExecStart=${PREFIX}/bin/clawlet serve
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$clawlet_home/.clawlet
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$service_file"
    
    # Reload systemd
    systemctl daemon-reload
    
    success "Installed systemd service at $service_file"
    info "Enable with: sudo systemctl enable --now clawlet"
}

# Install launchd plist (macOS)
install_launchd_plist() {
    local clawlet_home="$1"
    local plist_file="/Library/LaunchDaemons/com.openclaw.clawlet.plist"
    local log_dir="$clawlet_home/.clawlet/logs"

    info "Installing launchd plist..."

    cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.openclaw.clawlet</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>${PREFIX}/bin/clawlet</string>
        <string>serve</string>
    </array>
    
    <key>UserName</key>
    <string>$CLAWLET_USER</string>
    
    <key>GroupName</key>
    <string>staff</string>
    
    <key>WorkingDirectory</key>
    <string>$clawlet_home</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>CLAWLET_HOME</key>
        <string>$clawlet_home/.clawlet</string>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    
    <key>StandardOutPath</key>
    <string>$log_dir/clawlet.stdout.log</string>
    
    <key>StandardErrorPath</key>
    <string>$log_dir/clawlet.stderr.log</string>
    
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
EOF

    chmod 644 "$plist_file"
    chown root:wheel "$plist_file"

    success "Installed launchd plist at $plist_file"
    info "Load with: sudo launchctl load $plist_file"
}

print_post_install() {
    local installed_version="$1"

    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║          Clawlet installed successfully! 🐾              ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [[ -n "$installed_version" ]]; then
        echo -e "  Version: ${BOLD}${installed_version}${NC}"
        echo ""
    fi

    # Check if bin dir is in PATH
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        warn "NOTE: $BIN_DIR is not in your PATH"
        echo ""
        echo "    Add it to your shell profile:"
        echo ""
        echo -e "    ${BOLD}export PATH=\"$BIN_DIR:\$PATH\"${NC}"
        echo ""
    fi

    echo "  Next steps:"
    echo ""
    echo -e "    ${BOLD}1.${NC} Initialize clawlet:"
    echo -e "       ${BLUE}clawlet init${NC}"
    echo ""
    echo -e "    ${BOLD}2.${NC} Start the RPC server:"
    echo -e "       ${BLUE}clawlet serve${NC}"
    echo ""
    echo -e "    ${BOLD}3.${NC} Configure your policy:"
    echo -e "       ${BLUE}$CONFIG_DIR/policy.yaml${NC}"
    echo ""
    echo "  For help, run: clawlet --help"
    echo "  Documentation: https://github.com/${GITHUB_REPO}"
    echo ""
}

print_post_install_isolated() {
    local installed_version="$1"
    local os="$2"
    local clawlet_home="$3"

    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║    Clawlet installed in isolated mode! 🐾🔒              ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [[ -n "$installed_version" ]]; then
        echo -e "  Version: ${BOLD}${installed_version}${NC}"
    fi
    echo -e "  Mode:    ${BOLD}Isolated (dedicated user)${NC}"
    echo -e "  User:    ${BOLD}$CLAWLET_USER${NC}"
    echo -e "  Home:    ${BOLD}$clawlet_home/.clawlet${NC}"
    echo ""

    echo -e "  ${BOLD}Security:${NC}"
    echo "    - Keystore isolated from agent users"
    echo "    - Data directory: 700 permissions"
    echo "    - RPC binds to 127.0.0.1 only"
    echo ""

    echo -e "  ${BOLD}Next steps:${NC}"
    echo ""
    echo -e "    ${BOLD}1.${NC} Initialize keystore (as clawlet user):"
    echo -e "       ${BLUE}sudo -u $CLAWLET_USER clawlet init${NC}"
    echo ""

    if [[ "$os" == "linux" ]]; then
        echo -e "    ${BOLD}2.${NC} Start the service:"
        echo -e "       ${BLUE}sudo systemctl enable --now clawlet${NC}"
        echo ""
        echo -e "    ${BOLD}3.${NC} View logs:"
        echo -e "       ${BLUE}sudo journalctl -u clawlet -f${NC}"
    else
        echo -e "    ${BOLD}2.${NC} Start the service:"
        echo -e "       ${BLUE}sudo launchctl load /Library/LaunchDaemons/com.openclaw.clawlet.plist${NC}"
        echo ""
        echo -e "    ${BOLD}3.${NC} View logs:"
        echo -e "       ${BLUE}tail -f $clawlet_home/.clawlet/logs/clawlet.stderr.log${NC}"
    fi
    echo ""

    echo -e "    ${BOLD}4.${NC} Configure RPC endpoints:"
    echo -e "       ${BLUE}sudo -u $CLAWLET_USER nano $clawlet_home/.clawlet/config.yaml${NC}"
    echo ""

    echo "  For help, run: clawlet --help"
    echo "  Documentation: https://github.com/${GITHUB_REPO}/blob/main/docs/deployment.md"
    echo ""
}

# === Main ===
main() {
    echo ""
    echo -e "${BOLD}Clawlet Installer${NC}"
    echo "================="
    echo ""

    local os arch
    os=$(detect_os)
    arch=$(detect_arch)
    info "Detected: $os ($arch)"

    if [[ "$ISOLATED" == true ]]; then
        info "Installing in isolated mode"
        ensure_root
    fi

    # macOS Intel requires building from source (no prebuilt binary)
    if [[ "$os" == "darwin" && "$arch" == "x86_64" && "$FROM_SOURCE" != true ]]; then
        warn "No pre-built binary available for macOS Intel (x86_64)"
        info "Automatically switching to --from-source build"
        FROM_SOURCE=true
    fi

    ensure_curl

    local tmp_dir=""
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "${tmp_dir:-}"' EXIT

    local binary_path=""
    local installed_version=""

    if [[ "$FROM_SOURCE" == true ]]; then
        info "Building from source (--from-source specified)..."
        binary_path=$(build_from_source "$tmp_dir")
        installed_version="(built from source)"
    else
        # Try to download pre-built binary
        if [[ -z "$VERSION" ]]; then
            info "Fetching latest release version..."
            VERSION=$(get_latest_version) || true
        fi

        if [[ -z "$VERSION" ]]; then
            die "No releases found. Use --from-source to build manually, or check https://github.com/${GITHUB_REPO}/releases"
        fi

        info "Version: $VERSION"
        binary_path=$(download_release "$os" "$arch" "$VERSION" "$tmp_dir") || true
        installed_version="$VERSION"

        if [[ -z "$binary_path" || ! -f "$binary_path" ]]; then
            echo ""
            warn "No pre-built binary available for $os/$arch (version: ${VERSION:-unknown})"
            echo ""
            info "You can install from source instead:"
            echo ""
            echo "    $0 --from-source"
            echo ""
            info "Or check for available releases at:"
            echo "    https://github.com/${GITHUB_REPO}/releases"
            echo ""
            die "Installation failed. See above for alternatives."
        fi
    fi

    install_binary "$binary_path"

    if [[ "$ISOLATED" == true ]]; then
        # Isolated mode setup
        create_clawlet_user "$os"
        
        local clawlet_home
        clawlet_home=$(get_clawlet_home "$os")
        
        create_isolated_data_dir "$clawlet_home"

        if [[ "$os" == "linux" ]]; then
            install_systemd_service "$clawlet_home"
        else
            install_launchd_plist "$clawlet_home"
        fi

        print_post_install_isolated "$installed_version" "$os" "$clawlet_home"
    else
        # Standard user mode
        create_config_dir
        print_post_install "$installed_version"
    fi
}

main "$@"

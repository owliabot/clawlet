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
#   --help             Show this help message
#

set -euo pipefail

# === Configuration ===
GITHUB_REPO="owliabot/clawlet"
DEFAULT_PREFIX="/usr/local"
CONFIG_DIR="$HOME/.clawlet"

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
    --help             Show this help message

EXAMPLES:
    # Install latest release binary
    ./install.sh

    # Install specific version
    ./install.sh --version v0.1.0

    # Install to custom prefix
    ./install.sh --prefix ~/.local

    # Build from source
    ./install.sh --from-source

    # Pipe from curl
    curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/install.sh | bash

EOF
    exit 0
}

# === Argument Parsing ===
PREFIX="$DEFAULT_PREFIX"
VERSION=""
FROM_SOURCE=false

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

    info "Downloading ${asset_name}..."
    
    local archive_path="${tmp_dir}/${asset_name}"
    if ! curl -fsSL -o "$archive_path" "$download_url" 2>/dev/null; then
        return 1
    fi

    info "Extracting..."
    tar -xzf "$archive_path" -C "$tmp_dir" || return 1

    # Find the binary
    local binary_path="${tmp_dir}/clawlet"
    if [[ ! -f "$binary_path" ]]; then
        # Try in subdirectory
        binary_path=$(find "$tmp_dir" -name "clawlet" -type f -perm -u+x | head -1)
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

    info "Cloning clawlet repository..."
    git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$tmp_dir/clawlet" || die "Failed to clone repository"

    info "Building clawlet (this may take a few minutes)..."
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
POLICY
        success "Created default policy at $CONFIG_DIR/policy.yaml"
    else
        warn "Policy file already exists, skipping"
    fi

    success "Configuration directory ready"
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

    ensure_curl

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

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
            die "No pre-built binary available for $os/$arch (version: ${VERSION:-unknown}). Use --from-source to build manually."
        fi
    fi

    install_binary "$binary_path"
    create_config_dir
    print_post_install "$installed_version"
}

main "$@"

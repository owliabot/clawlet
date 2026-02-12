#!/usr/bin/env bash
#
# Clawlet Installation Script
# https://github.com/owliabot/clawlet
#
# Usage:
#   ./install.sh [OPTIONS]
#
# Options:
#   --isolated      Install in isolated user mode (creates clawlet system user)
#   --prefix DIR    Install binary to DIR/bin (default: /usr/local)
#   --skip-build    Skip cargo build (use existing binary in target/release)
#   --yes           Skip confirmation prompts
#   --help          Show this help message
#

set -euo pipefail

# === Configuration ===
DEFAULT_PREFIX="/usr/local"
CLAWLET_USER="clawlet"
CLAWLET_GROUP="clawlet"
BINARY_NAME="clawlet"

# === Colors ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# === Helpers ===
info()    { echo -e "${BLUE}ℹ${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
error()   { echo -e "${RED}✗${NC} $1" >&2; }
die()     { error "$1"; exit 1; }

show_help() {
    cat << 'EOF'
Clawlet Installation Script

USAGE:
    install.sh [OPTIONS]

OPTIONS:
    --isolated      Install in isolated user mode:
                    - Creates clawlet system user (nologin shell)
                    - Sets binary ownership to root:clawlet (751)
                    - Initializes keystore under clawlet user's home
                    - Sets all data file permissions to 600
    --prefix DIR    Install binary to DIR/bin (default: /usr/local)
    --skip-build    Skip cargo build, use existing target/release binary
    --yes, -y       Skip confirmation prompts
    --help          Show this help message

MODES:
    Dev mode (default):
        Builds and installs the binary to PREFIX/bin with standard permissions.
        User manages their own ~/.clawlet directory.

    Isolated mode (--isolated, recommended):
        Creates a dedicated clawlet system user for UID isolation.
        All wallet data is owned by clawlet user (600), inaccessible to
        the current user or AI agents. See docs/security-boundary-analysis.md.

EXAMPLES:
    # Dev mode install
    ./install.sh

    # Isolated mode (recommended for production)
    sudo ./install.sh --isolated

    # Custom prefix, no prompts
    ./install.sh --prefix ~/.local --yes

EOF
    exit 0
}

confirm() {
    local prompt="$1"
    if [[ "$SKIP_CONFIRM" == "true" ]]; then
        return 0
    fi
    echo -en "${YELLOW}?${NC} $prompt [y/N] "
    read -r response < /dev/tty
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        *)       die "Unsupported operating system: $os" ;;
    esac
}

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        die "Isolated mode requires root privileges. Please run with sudo."
    fi
}

# === Argument Parsing ===
PREFIX="$DEFAULT_PREFIX"
ISOLATED="false"
SKIP_BUILD="false"
SKIP_CONFIRM="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        --isolated)
            ISOLATED="true"
            shift
            ;;
        --prefix)
            PREFIX="${2:-}"
            if [[ -z "$PREFIX" ]]; then
                die "--prefix requires a directory argument"
            fi
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD="true"
            shift
            ;;
        --yes|-y)
            SKIP_CONFIRM="true"
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
BINARY_PATH="$BIN_DIR/$BINARY_NAME"

# === Build ===

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64)  echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *)       die "Unsupported architecture: $arch" ;;
    esac
}

download_binary() {
    local os arch
    os=$(detect_os)
    arch=$(detect_arch)

    info "Detecting latest release..."

    # Use GitHub API to find the latest release asset matching our OS/arch
    local api_url="https://api.github.com/repos/owliabot/clawlet/releases/latest"
    local release_json
    release_json=$(curl -fsSL "$api_url") || die "Failed to fetch latest release info"

    # Find the asset URL matching our platform: clawlet-{version}-{arch}-{os}.tar.gz
    local asset_url
    asset_url=$(echo "$release_json" | grep -o "\"browser_download_url\": *\"[^\"]*${arch}-${os}\\.tar\\.gz\"" | head -1 | sed 's/.*"browser_download_url": *"//;s/"$//')

    if [[ -z "$asset_url" ]]; then
        die "No release binary found for ${os}/${arch}. You may need to build from source."
    fi

    info "Downloading $BINARY_NAME for ${os}/${arch}..."
    info "URL: $asset_url"

    mkdir -p target/release
    local tmpfile
    tmpfile=$(mktemp)
    curl -fsSL -o "$tmpfile" "$asset_url" || die "Download failed"
    tar -xzf "$tmpfile" -C target/release || die "Extraction failed"
    rm -f "$tmpfile"

    if [[ ! -f "target/release/$BINARY_NAME" ]]; then
        die "Downloaded archive did not contain '$BINARY_NAME'"
    fi
    chmod 751 "target/release/$BINARY_NAME"
    success "Downloaded $BINARY_NAME for ${os}/${arch}"
}

build_binary() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        if [[ ! -f "target/release/$BINARY_NAME" ]]; then
            die "No binary found at target/release/$BINARY_NAME (--skip-build requires a pre-built binary)"
        fi
        info "Using existing binary at target/release/$BINARY_NAME"
        return 0
    fi

    # Prefer building from local source when in a repo checkout
    if [[ -f "Cargo.toml" ]] && command -v cargo >/dev/null 2>&1; then
        info "Building from local source..."
        cargo build --release -p clawlet-cli || die "Build failed"
        success "Build complete"
    elif download_binary; then
        # Fallback to downloading pre-built binary (works with curl | bash flow)
        :
    else
        die "Cannot build from source (Cargo.toml or cargo not found) and failed to download pre-built binary"
    fi
}

# === Standard Install ===

install_standard() {
    info "Installing to $BINARY_PATH..."
    if mkdir -p "$BIN_DIR" 2>/dev/null; then
        :
    else
        sudo mkdir -p "$BIN_DIR"
    fi
    if cp "target/release/$BINARY_NAME" "$BINARY_PATH" 2>/dev/null; then
        chmod 751 "$BINARY_PATH"
    else
        sudo cp "target/release/$BINARY_NAME" "$BINARY_PATH"
        sudo chmod 751 "$BINARY_PATH"
    fi
    success "Binary installed to $BINARY_PATH (751)"
}

start_standard() {
    echo ""
    info "Starting clawlet..."
    echo ""
    "$BINARY_PATH" start --agent owliabot
}

# === Isolated Mode Install ===

create_system_user_linux() {
    local user_exists=false
    if id "$CLAWLET_USER" &>/dev/null; then
        user_exists=true
        info "User '$CLAWLET_USER' already exists"
    fi

    if ! getent group "$CLAWLET_GROUP" >/dev/null 2>&1; then
        info "Creating system group '$CLAWLET_GROUP'..."
        if groupadd --system "$CLAWLET_GROUP" 2>/dev/null; then
            :
        else
            sudo groupadd --system "$CLAWLET_GROUP" || die "Failed to create group '$CLAWLET_GROUP'"
        fi
    fi

    if [[ "$user_exists" == "true" ]]; then
        info "Ensuring '$CLAWLET_USER' is a member of '$CLAWLET_GROUP'..."
        if usermod -aG "$CLAWLET_GROUP" "$CLAWLET_USER" 2>/dev/null; then
            :
        else
            sudo usermod -aG "$CLAWLET_GROUP" "$CLAWLET_USER" \
                || die "Failed to add user '$CLAWLET_USER' to group '$CLAWLET_GROUP'"
        fi
        success "User '$CLAWLET_USER' group membership verified"
        return 0
    fi

    info "Creating system user '$CLAWLET_USER'..."
    if useradd --system --create-home --shell /usr/sbin/nologin --gid "$CLAWLET_GROUP" "$CLAWLET_USER" 2>/dev/null; then
        :
    else
        sudo useradd --system --create-home --shell /usr/sbin/nologin --gid "$CLAWLET_GROUP" "$CLAWLET_USER" \
            || die "Failed to create user '$CLAWLET_USER'"
    fi
    success "System user '$CLAWLET_USER' created"
}

create_system_user_macos() {
    if id "$CLAWLET_USER" &>/dev/null; then
        info "User '$CLAWLET_USER' already exists"

        # Ensure group exists and user is a member even when reusing an existing user
        if ! dscl . -read "/Groups/$CLAWLET_GROUP" &>/dev/null; then
            info "Creating group '$CLAWLET_GROUP'..."
            local gid=399
            while dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | grep -q "^${gid}$"; do
                gid=$((gid - 1))
                if [[ $gid -lt 300 ]]; then
                    die "Could not find an available GID for system group"
                fi
            done
            dscl . -create "/Groups/$CLAWLET_GROUP"
            dscl . -create "/Groups/$CLAWLET_GROUP" PrimaryGroupID "$gid"
            success "Group '$CLAWLET_GROUP' created (GID=$gid)"
        fi

        # Ensure user is a member of the group
        local current_gid
        current_gid=$(dscl . -read "/Groups/$CLAWLET_GROUP" PrimaryGroupID 2>/dev/null | awk '{print $2}')
        local user_gid
        user_gid=$(dscl . -read "/Users/$CLAWLET_USER" PrimaryGroupID 2>/dev/null | awk '{print $2}')
        if [[ "$user_gid" != "$current_gid" ]]; then
            dscl . -create "/Users/$CLAWLET_USER" PrimaryGroupID "$current_gid"
            info "Updated '$CLAWLET_USER' primary group to '$CLAWLET_GROUP'"
        fi

        # Ensure home directory exists with correct permissions.
        mkdir -p "/var/$CLAWLET_USER"
        chown "$CLAWLET_USER:$CLAWLET_GROUP" "/var/$CLAWLET_USER" 2>/dev/null || true
        chmod 700 "/var/$CLAWLET_USER" 2>/dev/null || true

        success "User '$CLAWLET_USER' group membership verified"
        return 0
    fi

    info "Creating system user '$CLAWLET_USER'..."

    # Find an unused UID in the system range (< 500)
    local uid=399
    while dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}' | grep -q "^${uid}$"; do
        uid=$((uid - 1))
        if [[ $uid -lt 300 ]]; then
            die "Could not find an available UID for system user"
        fi
    done

    # Find an unused GID (use same starting point as UID)
    local gid="$uid"
    while dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | grep -q "^${gid}$"; do
        gid=$((gid - 1))
        if [[ $gid -lt 300 ]]; then
            die "Could not find an available GID for system group"
        fi
    done

    # Create group if it doesn't exist
    if ! dscl . -read "/Groups/$CLAWLET_GROUP" &>/dev/null; then
        dscl . -create "/Groups/$CLAWLET_GROUP"
        dscl . -create "/Groups/$CLAWLET_GROUP" PrimaryGroupID "$gid"
    fi

    gid=$(dscl . -read "/Groups/$CLAWLET_GROUP" PrimaryGroupID 2>/dev/null | awk '{print $2}')

    dscl . -create "/Users/$CLAWLET_USER"
    dscl . -create "/Users/$CLAWLET_USER" UserShell /usr/bin/false
    dscl . -create "/Users/$CLAWLET_USER" UniqueID "$uid"
    dscl . -create "/Users/$CLAWLET_USER" PrimaryGroupID "$gid"
    dscl . -create "/Users/$CLAWLET_USER" NFSHomeDirectory "/var/$CLAWLET_USER"

    mkdir -p "/var/$CLAWLET_USER"
    chown "$CLAWLET_USER:$CLAWLET_GROUP" "/var/$CLAWLET_USER"
    chmod 700 "/var/$CLAWLET_USER"

    success "System user '$CLAWLET_USER' created (UID=$uid)"
}

install_binary_isolated() {
    info "Installing binary to $BINARY_PATH (root:$CLAWLET_GROUP 751)..."

    if mkdir -p "$BIN_DIR" 2>/dev/null; then
        :
    else
        sudo mkdir -p "$BIN_DIR"
    fi

    # Ensure group exists (Linux)
    if [[ "$(detect_os)" == "linux" ]]; then
        if ! getent group "$CLAWLET_GROUP" >/dev/null 2>&1; then
            # User creation above should have created the group, but check anyway
            groupadd "$CLAWLET_GROUP" 2>/dev/null || true
        fi
    fi

    cp "target/release/$BINARY_NAME" "$BINARY_PATH"
    chown "root:$CLAWLET_GROUP" "$BINARY_PATH"
    chmod 751 "$BINARY_PATH"

    success "Binary installed (root:$CLAWLET_GROUP, 751)"
}

verify_data_permissions() {
    local clawlet_home
    local os
    os=$(detect_os)

    case "$os" in
        linux)  clawlet_home=$(eval echo "~$CLAWLET_USER") ;;
        darwin) clawlet_home="/var/$CLAWLET_USER" ;;
    esac

    local data_dir="$clawlet_home/.clawlet"

    if [[ -d "$data_dir" ]]; then
        info "Verifying data directory permissions..."

        # Ensure directory is 700
        chmod 700 "$data_dir"
        chown "$CLAWLET_USER:$CLAWLET_GROUP" "$data_dir"

        # Ensure all files are 600
        find "$data_dir" -type f -exec chmod 600 {} \;
        find "$data_dir" -type d -exec chmod 700 {} \;
        find "$data_dir" \( -type f -o -type d \) -exec chown "$CLAWLET_USER:$CLAWLET_GROUP" {} \;

        success "Data directory permissions verified ($data_dir)"
    else
        info "Data directory not yet created ($data_dir)"
        info "It will be created when you run: sudo -H -u $CLAWLET_USER $BINARY_NAME init"
    fi
}

print_isolated_post_install() {
    local clawlet_home
    local os
    os=$(detect_os)

    case "$os" in
        linux)  clawlet_home=$(eval echo "~$CLAWLET_USER") ;;
        darwin) clawlet_home="/var/$CLAWLET_USER" ;;
    esac

    echo ""
    echo -e "${BOLD}Isolated mode installed successfully!${NC}"
    echo ""
}

start_isolated() {
    local clawlet_home
    local os
    os=$(detect_os)

    case "$os" in
        linux)  clawlet_home=$(eval echo "~$CLAWLET_USER") ;;
        darwin) clawlet_home="/var/$CLAWLET_USER" ;;
    esac

    info "Starting clawlet daemon..."
    echo ""
    sudo -H -u "$CLAWLET_USER" "$BINARY_PATH" start --agent owliabot --daemon

    echo ""
    echo "Useful commands:"
    echo ""
    echo "  # View logs:"
    echo "  sudo tail -f $clawlet_home/.clawlet/clawlet.log"
    echo ""
    echo "  # Stop daemon:"
    echo "  sudo -H -u $CLAWLET_USER $BINARY_NAME stop"
    echo ""
    echo "  # Clear sudo cache (security best practice):"
    echo "  sudo -k"
    echo ""
}

install_isolated() {
    local os
    os=$(detect_os)

    echo ""
    echo -e "${BOLD}Isolated Mode Installation${NC}"
    echo "=========================="
    echo ""
    info "This will:"
    echo "    - Create system user '$CLAWLET_USER' (nologin shell)"
    echo "    - Install binary as root:$CLAWLET_GROUP with mode 751"
    echo "    - Verify data directory permissions (if exists)"
    echo ""

    if ! confirm "Proceed with isolated mode install?"; then
        info "Installation cancelled"
        exit 0
    fi

    # Create system user
    case "$os" in
        linux)  create_system_user_linux ;;
        darwin) create_system_user_macos ;;
    esac

    # Install binary with restricted permissions
    install_binary_isolated

    # Verify existing data permissions (if upgrading)
    verify_data_permissions

    # Print post-install message
    print_isolated_post_install

    # Auto-start daemon
    start_isolated
}

# === Main ===

main() {
    echo ""
    echo -e "${BOLD}Clawlet Installer${NC}"
    echo "=================="
    echo ""

    if [[ "$ISOLATED" == "true" ]]; then
        ensure_root
    fi

    build_binary

    if [[ "$ISOLATED" == "true" ]]; then
        install_isolated
    else
        install_standard
        start_standard
    fi
}

main "$@"

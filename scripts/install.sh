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
                    - Sets binary ownership to root:clawlet (750)
                    - Initializes keystore under clawlet user's home
                    - Sets all data file permissions to 600
    --prefix DIR    Install binary to DIR/bin (default: /usr/local)
    --skip-build    Skip cargo build, use existing target/release binary
    --yes, -y       Skip confirmation prompts
    --help          Show this help message

MODES:
    Standard mode (default):
        Builds and installs the binary to PREFIX/bin with standard permissions.
        User manages their own ~/.clawlet directory.

    Isolated mode (--isolated):
        Creates a dedicated clawlet system user for UID isolation.
        All wallet data is owned by clawlet user (600), inaccessible to
        the current user or AI agents. See docs/security-boundary-analysis.md.

EXAMPLES:
    # Standard install
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
    read -r response
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

build_binary() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        if [[ ! -f "target/release/$BINARY_NAME" ]]; then
            die "No binary found at target/release/$BINARY_NAME (--skip-build requires a pre-built binary)"
        fi
        info "Using existing binary at target/release/$BINARY_NAME"
        return 0
    fi

    info "Building $BINARY_NAME (release)..."
    cargo build --release -p clawlet-cli || die "Build failed"
    success "Build complete"
}

# === Standard Install ===

install_standard() {
    info "Installing to $BINARY_PATH..."
    sudo cp "target/release/$BINARY_NAME" "$BINARY_PATH"
    sudo chmod 755 "$BINARY_PATH"
    success "Binary installed to $BINARY_PATH (755)"

    echo ""
    info "Standard mode installed. To get started:"
    echo ""
    echo "    $BINARY_NAME init        # Create keystore + set password"
    echo "    $BINARY_NAME serve       # Start daemon"
    echo ""
}

# === Isolated Mode Install ===

create_system_user_linux() {
    if id "$CLAWLET_USER" &>/dev/null; then
        info "User '$CLAWLET_USER' already exists"
        return 0
    fi

    info "Creating system user '$CLAWLET_USER'..."
    useradd --system --create-home --shell /usr/sbin/nologin "$CLAWLET_USER" \
        || die "Failed to create user '$CLAWLET_USER'"
    success "System user '$CLAWLET_USER' created"
}

create_system_user_macos() {
    if id "$CLAWLET_USER" &>/dev/null; then
        info "User '$CLAWLET_USER' already exists"
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

    # Create group if it doesn't exist
    if ! dscl . -read "/Groups/$CLAWLET_GROUP" &>/dev/null; then
        dscl . -create "/Groups/$CLAWLET_GROUP"
        dscl . -create "/Groups/$CLAWLET_GROUP" PrimaryGroupID "$uid"
    fi

    local gid
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
    info "Installing binary to $BINARY_PATH (root:$CLAWLET_GROUP 750)..."

    # Ensure group exists (Linux)
    if [[ "$(detect_os)" == "linux" ]]; then
        if ! getent group "$CLAWLET_GROUP" >/dev/null 2>&1; then
            # User creation above should have created the group, but check anyway
            groupadd "$CLAWLET_GROUP" 2>/dev/null || true
        fi
    fi

    cp "target/release/$BINARY_NAME" "$BINARY_PATH"
    chown "root:$CLAWLET_GROUP" "$BINARY_PATH"
    chmod 750 "$BINARY_PATH"

    success "Binary installed (root:$CLAWLET_GROUP, 750)"
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
        find "$data_dir" -exec chown "$CLAWLET_USER:$CLAWLET_GROUP" {} \;

        success "Data directory permissions verified ($data_dir)"
    else
        info "Data directory not yet created ($data_dir)"
        info "It will be created when you run: sudo -u $CLAWLET_USER $BINARY_NAME init"
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
    echo "Next steps:"
    echo ""
    echo "  1. Initialize keystore (password >= 8 chars, upper+lower+digit+symbol):"
    echo "     sudo -u $CLAWLET_USER $BINARY_NAME init"
    echo ""
    echo "  2. Edit configuration:"
    echo "     sudo -u $CLAWLET_USER nano $clawlet_home/.clawlet/config.yaml"
    echo ""
    echo "  3. Start daemon:"
    echo "     sudo -u $CLAWLET_USER $BINARY_NAME serve"
    echo ""
    echo "  4. Clear sudo cache (security best practice):"
    echo "     sudo -k"
    echo ""
    echo "Security verification:"
    echo ""
    echo "  # Binary should be root:$CLAWLET_GROUP 750"
    echo "  ls -la $BINARY_PATH"
    echo ""
    echo "  # Data dir should be $CLAWLET_USER:$CLAWLET_GROUP 700, files 600"
    echo "  sudo ls -la $clawlet_home/.clawlet/"
    echo ""
    echo "  # Current user should NOT be able to read data"
    echo "  cat $clawlet_home/.clawlet/policy.yaml  # Should fail with permission denied"
    echo ""
    echo "See docs/security-boundary-analysis.md for the full security model."
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
    echo "    - Install binary as root:$CLAWLET_GROUP with mode 750"
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

    # Print post-install instructions
    print_isolated_post_install
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
    fi
}

main "$@"

#!/usr/bin/env bash
#
# Clawlet Uninstallation Script
# https://github.com/owliabot/clawlet
#
# Usage:
#   ./uninstall.sh [OPTIONS]
#
# Options:
#   --prefix DIR    Look for binary in DIR/bin instead of /usr/local/bin
#   --purge         Also remove configuration directory (~/.clawlet)
#   --yes           Skip confirmation prompts
#   --help          Show this help message
#

set -euo pipefail

# === Configuration ===
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
Clawlet Uninstallation Script

USAGE:
    uninstall.sh [OPTIONS]

OPTIONS:
    --prefix DIR    Look for binary in DIR/bin instead of /usr/local/bin
    --purge         Also remove configuration directory (~/.clawlet)
                    WARNING: This will delete your keys and logs!
    --yes, -y       Skip confirmation prompts
    --help          Show this help message

EXAMPLES:
    # Uninstall binary only (keeps config)
    ./uninstall.sh

    # Uninstall everything including config
    ./uninstall.sh --purge

    # Uninstall from custom location without prompts
    ./uninstall.sh --prefix ~/.local --yes

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

# === Argument Parsing ===
PREFIX="$DEFAULT_PREFIX"
PURGE="false"
SKIP_CONFIRM="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        --prefix)
            PREFIX="${2:-}"
            if [[ -z "$PREFIX" ]]; then
                die "--prefix requires a directory argument"
            fi
            shift 2
            ;;
        --purge)
            PURGE="true"
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
BINARY_PATH="$BIN_DIR/clawlet"

# === Uninstallation ===
remove_binary() {
    if [[ ! -f "$BINARY_PATH" ]]; then
        warn "Binary not found at $BINARY_PATH"
        return 0
    fi

    info "Removing binary at $BINARY_PATH..."
    
    if [[ ! -w "$BINARY_PATH" && ! -w "$BIN_DIR" ]]; then
        sudo rm -f "$BINARY_PATH" || die "Failed to remove binary (try running with sudo)"
    else
        rm -f "$BINARY_PATH" || die "Failed to remove binary"
    fi
    
    success "Binary removed"
}

remove_config() {
    if [[ ! -d "$CONFIG_DIR" ]]; then
        warn "Configuration directory not found at $CONFIG_DIR"
        return 0
    fi

    echo ""
    warn "This will permanently delete:"
    echo "    - Keys in $CONFIG_DIR/keys/"
    echo "    - Logs in $CONFIG_DIR/logs/"
    echo "    - Policy at $CONFIG_DIR/policy.yaml"
    echo ""

    if ! confirm "Are you sure you want to delete $CONFIG_DIR?"; then
        info "Skipping configuration removal"
        return 0
    fi

    info "Removing configuration directory..."
    rm -rf "$CONFIG_DIR" || die "Failed to remove configuration directory"
    success "Configuration directory removed"
}

# === Main ===
main() {
    echo ""
    echo -e "${BOLD}Clawlet Uninstaller${NC}"
    echo "==================="
    echo ""

    if [[ "$PURGE" == "true" ]]; then
        warn "Running in purge mode - will remove config files"
        echo ""
    fi

    if ! confirm "Uninstall clawlet from $BIN_DIR?"; then
        info "Uninstallation cancelled"
        exit 0
    fi

    remove_binary

    if [[ "$PURGE" == "true" ]]; then
        remove_config
    else
        if [[ -d "$CONFIG_DIR" ]]; then
            echo ""
            info "Configuration directory preserved at $CONFIG_DIR"
            info "To remove it, run: ./uninstall.sh --purge"
        fi
    fi

    echo ""
    echo -e "${GREEN}${BOLD}Clawlet has been uninstalled${NC}"
    echo ""
}

main "$@"

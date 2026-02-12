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
#   --isolated      Uninstall isolated mode (service, user, data)
#   --skip-service  Skip service removal (for Docker/testing)
#   --yes           Skip confirmation prompts
#   --help          Show this help message
#

set -euo pipefail

# === Configuration ===
DEFAULT_PREFIX="/usr/local"
CONFIG_DIR="$HOME/.clawlet"
CLAWLET_USER="clawlet"

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
    --isolated      Uninstall isolated mode installation:
                    - Stops and removes systemd/launchd service
                    - Optionally removes clawlet system user
                    - Removes /home/clawlet or /var/clawlet data
    --skip-service  Skip service removal (useful for Docker)
    --yes, -y       Skip confirmation prompts
    --help          Show this help message

EXAMPLES:
    # Uninstall binary only (keeps config)
    ./uninstall.sh

    # Uninstall everything including config
    ./uninstall.sh --purge

    # Uninstall isolated mode installation
    sudo ./uninstall.sh --isolated

    # Uninstall isolated mode with full cleanup
    sudo ./uninstall.sh --isolated --purge

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
        die "Isolated mode uninstall requires root privileges. Please run with sudo."
    fi
}

# === Argument Parsing ===
PREFIX="$DEFAULT_PREFIX"
PURGE="false"
ISOLATED="false"
SKIP_SERVICE="false"
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
        --isolated)
            ISOLATED="true"
            shift
            ;;
        --skip-service)
            SKIP_SERVICE="true"
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

# === Stop Running Daemon ===

stop_daemon() {
    # Try using `clawlet stop` if binary exists
    if [[ -f "$BINARY_PATH" ]]; then
        info "Stopping clawlet daemon..."
        if "$BINARY_PATH" stop 2>/dev/null; then
            success "Daemon stopped"
            return 0
        fi
    fi

    # Fallback: check PID file
    local pid_file="$CONFIG_DIR/clawlet.pid"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            info "Stopping clawlet daemon (PID $pid)..."
            kill "$pid" 2>/dev/null || true
            # Wait up to 5 seconds for clean exit
            local i=0
            while [[ $i -lt 10 ]] && kill -0 "$pid" 2>/dev/null; do
                sleep 0.5
                i=$((i + 1))
            done
            if kill -0 "$pid" 2>/dev/null; then
                warn "Daemon did not exit gracefully, sending SIGKILL..."
                kill -9 "$pid" 2>/dev/null || true
            fi
            success "Daemon stopped"
        fi
        rm -f "$pid_file"
    fi
}

stop_daemon_isolated() {
    local os
    os=$(detect_os)
    local clawlet_home

    case "$os" in
        linux)  clawlet_home=$(eval echo "~$CLAWLET_USER") ;;
        darwin) clawlet_home="/var/$CLAWLET_USER" ;;
    esac

    # Try using `clawlet stop` as the clawlet user
    if [[ -f "$BINARY_PATH" ]]; then
        info "Stopping clawlet daemon..."
        if sudo -H -u "$CLAWLET_USER" "$BINARY_PATH" stop 2>/dev/null; then
            success "Daemon stopped"
            return 0
        fi
    fi

    # Fallback: check PID file
    local pid_file="$clawlet_home/.clawlet/clawlet.pid"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            info "Stopping clawlet daemon (PID $pid)..."
            kill "$pid" 2>/dev/null || true
            local i=0
            while [[ $i -lt 10 ]] && kill -0 "$pid" 2>/dev/null; do
                sleep 0.5
                i=$((i + 1))
            done
            if kill -0 "$pid" 2>/dev/null; then
                warn "Daemon did not exit gracefully, sending SIGKILL..."
                kill -9 "$pid" 2>/dev/null || true
            fi
            success "Daemon stopped"
        fi
        rm -f "$pid_file"
    fi
}

# === Uninstallation Functions ===

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

# === Isolated Mode Uninstallation ===

stop_systemd_service() {
    if ! command -v systemctl &>/dev/null; then
        return 0
    fi

    if systemctl is-active --quiet clawlet 2>/dev/null; then
        info "Stopping clawlet service..."
        systemctl stop clawlet || warn "Failed to stop service"
        success "Service stopped"
    fi

    if systemctl is-enabled --quiet clawlet 2>/dev/null; then
        info "Disabling clawlet service..."
        systemctl disable clawlet || warn "Failed to disable service"
        success "Service disabled"
    fi
}

remove_systemd_service() {
    local service_file="/etc/systemd/system/clawlet.service"
    
    if [[ ! -f "$service_file" ]]; then
        return 0
    fi

    info "Removing systemd service file..."
    rm -f "$service_file" || die "Failed to remove service file"
    systemctl daemon-reload
    success "Systemd service removed"
}

stop_launchd_service() {
    local plist_file="/Library/LaunchDaemons/com.openclaw.clawlet.plist"
    
    if [[ ! -f "$plist_file" ]]; then
        return 0
    fi

    # Check if loaded
    if launchctl list | grep -q "com.openclaw.clawlet"; then
        info "Stopping clawlet service..."
        launchctl unload "$plist_file" 2>/dev/null || warn "Failed to unload service"
        success "Service stopped"
    fi
}

remove_launchd_service() {
    local plist_file="/Library/LaunchDaemons/com.openclaw.clawlet.plist"
    
    if [[ ! -f "$plist_file" ]]; then
        return 0
    fi

    info "Removing launchd plist..."
    rm -f "$plist_file" || die "Failed to remove plist"
    success "Launchd plist removed"
}

remove_clawlet_user_linux() {
    if ! id "$CLAWLET_USER" &>/dev/null; then
        return 0
    fi

    echo ""
    warn "User '$CLAWLET_USER' exists with home directory"
    
    if ! confirm "Remove user '$CLAWLET_USER' and home directory?"; then
        info "Skipping user removal"
        return 0
    fi

    info "Removing user '$CLAWLET_USER'..."
    
    # Kill any processes owned by user
    pkill -u "$CLAWLET_USER" 2>/dev/null || true
    sleep 1
    
    # Remove user and home directory
    userdel -r "$CLAWLET_USER" 2>/dev/null || userdel "$CLAWLET_USER" || die "Failed to remove user"
    
    success "User '$CLAWLET_USER' removed"
}

remove_clawlet_user_macos() {
    if ! id "$CLAWLET_USER" &>/dev/null; then
        return 0
    fi

    echo ""
    warn "User '$CLAWLET_USER' exists with home directory"
    
    if ! confirm "Remove user '$CLAWLET_USER' and home directory?"; then
        info "Skipping user removal"
        return 0
    fi

    info "Removing user '$CLAWLET_USER'..."
    
    # Kill any processes owned by user
    pkill -u "$CLAWLET_USER" 2>/dev/null || true
    sleep 1
    
    local clawlet_home="/var/$CLAWLET_USER"
    
    # Remove user via dscl
    dscl . -delete "/Users/$CLAWLET_USER" || die "Failed to remove user"
    
    # Remove home directory
    if [[ -d "$clawlet_home" ]]; then
        rm -rf "$clawlet_home" || warn "Failed to remove home directory"
    fi
    
    success "User '$CLAWLET_USER' removed"
}

remove_isolated_data() {
    local os="$1"
    local clawlet_home
    
    case "$os" in
        linux)  clawlet_home="/home/$CLAWLET_USER" ;;
        darwin) clawlet_home="/var/$CLAWLET_USER" ;;
    esac

    # Also clean up legacy macOS path (/Users/$CLAWLET_USER) from older installs.
    if [[ "$os" == "darwin" ]]; then
        local legacy_home="/Users/$CLAWLET_USER"
        local legacy_data="$legacy_home/.clawlet"
        if [[ -d "$legacy_data" ]]; then
            warn "Found legacy data at $legacy_data — removing"
            rm -rf "$legacy_data" || warn "Failed to remove legacy data directory"
        fi
        if [[ -d "$legacy_home" ]]; then
            # Older isolated installs used a dedicated macOS user home at /Users/clawlet.
            warn "Found legacy macOS home at $legacy_home — removing"
            rm -rf "$legacy_home" || warn "Failed to remove legacy home directory"
        fi
    fi

    local data_dir="$clawlet_home/.clawlet"
    
    if [[ ! -d "$data_dir" ]]; then
        return 0
    fi

    echo ""
    warn "This will permanently delete isolated mode data:"
    echo "    - Keystore in $data_dir/keystore/"
    echo "    - Logs in $data_dir/logs/"
    echo "    - Config at $data_dir/config.yaml"
    echo "    - Policy at $data_dir/policy.yaml"
    echo "    - Audit log at $data_dir/audit.jsonl"
    echo ""

    if ! confirm "Are you sure you want to delete $data_dir?"; then
        info "Skipping data directory removal"
        return 0
    fi

    info "Removing data directory..."
    rm -rf "$data_dir" || die "Failed to remove data directory"
    success "Data directory removed"
}

uninstall_isolated() {
    local os
    os=$(detect_os)
    
    info "Uninstalling isolated mode installation..."
    echo ""

    # Stop running daemon (PID-file based)
    stop_daemon_isolated

    # Stop and remove service
    if [[ "$SKIP_SERVICE" != "true" ]]; then
        if [[ "$os" == "linux" ]]; then
            stop_systemd_service
            remove_systemd_service
        else
            stop_launchd_service
            remove_launchd_service
        fi
    else
        info "Skipping service removal (--skip-service)"
    fi

    # Remove binary
    remove_binary

    if [[ "$PURGE" == "true" ]]; then
        # Remove data directory
        remove_isolated_data "$os"
        
        # Remove user (this also removes home directory)
        if [[ "$os" == "linux" ]]; then
            remove_clawlet_user_linux
        else
            remove_clawlet_user_macos
        fi
    else
        echo ""
        info "Data preserved. To remove completely, run:"
        echo ""
        echo "    sudo $0 --isolated --purge"
        echo ""
    fi
}

# === Main ===
main() {
    echo ""
    echo -e "${BOLD}Clawlet Uninstaller${NC}"
    echo "==================="
    echo ""

    if [[ "$ISOLATED" == "true" ]]; then
        ensure_root
        
        if [[ "$PURGE" == "true" ]]; then
            warn "Running in isolated + purge mode - will remove service, data, and user"
        else
            info "Running in isolated mode - will remove service and binary"
        fi
        echo ""
        
        if ! confirm "Proceed with isolated mode uninstall?"; then
            info "Uninstallation cancelled"
            exit 0
        fi
        
        uninstall_isolated
    else
        # Standard uninstall
        if [[ "$PURGE" == "true" ]]; then
            warn "Running in purge mode - will remove config files"
            echo ""
        fi

        if ! confirm "Uninstall clawlet from $BIN_DIR?"; then
            info "Uninstallation cancelled"
            exit 0
        fi

        stop_daemon
        remove_binary

        if [[ "$PURGE" == "true" ]]; then
            remove_config
        else
            if [[ -d "$CONFIG_DIR" ]]; then
                echo ""
                info "Configuration directory preserved at $CONFIG_DIR"
                info "To remove it, run: $0 --purge"
            fi
        fi
    fi

    echo ""
    echo -e "${GREEN}${BOLD}Clawlet has been uninstalled${NC}"
    echo ""
}

main "$@"

#!/usr/bin/env bash
# install.sh — Build and install the clawlet binary with proper permissions.
set -euo pipefail

BINARY_NAME="clawlet"
INSTALL_DIR="/usr/local/bin"
GROUP_NAME="clawlet"

# Check that the clawlet group exists
if ! getent group "$GROUP_NAME" >/dev/null 2>&1; then
    echo "Error: group '$GROUP_NAME' does not exist." >&2
    echo "Create it with:  sudo groupadd $GROUP_NAME" >&2
    exit 1
fi

# Build release binary
echo "Building $BINARY_NAME (release)..."
cargo build --release -p clawlet-cli

# Install with correct ownership and permissions
echo "Installing to $INSTALL_DIR/$BINARY_NAME..."
sudo cp "target/release/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
sudo chown "root:$GROUP_NAME" "$INSTALL_DIR/$BINARY_NAME"
sudo chmod 750 "$INSTALL_DIR/$BINARY_NAME"

echo "Done. Installed $INSTALL_DIR/$BINARY_NAME (root:$GROUP_NAME, 750)."

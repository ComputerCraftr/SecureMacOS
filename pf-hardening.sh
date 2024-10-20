#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

# Define the name of the custom anchor and the paths
ANCHOR_NAME="pf-hardening"
ANCHOR_FILE="/etc/pf.anchors/$ANCHOR_NAME"
PF_CONF="/etc/pf.conf"
BACKUP_FILE="/etc/pf.conf.backup"

# Function to check if the custom rules are already installed
is_installed() {
    grep -q "anchor \"$ANCHOR_NAME\"" "$PF_CONF" && [ -f "$ANCHOR_FILE" ]
}

# Function to install or reinstall the custom rules
install_pf_rules() {
    echo "Creating custom pf ruleset in $ANCHOR_FILE..."
    tee "$ANCHOR_FILE" >/dev/null <<EOF
# Allow loopback traffic for internal communications
set skip on lo0

# Normalize incoming traffic to reassemble fragments
scrub in all

# Default deny policy: Block everything by default
block all

# Allow necessary ICMP for PMTUD and diagnostic tools in IPv4
pass in inet proto icmp icmp-type 8 no state        # Echo Request (ping)
pass in inet proto icmp icmp-type 3 code 4 no state # Destination Unreachable - Frag Needed (PMTUD)
pass in inet proto icmp icmp-type 11 no state       # Time Exceeded (traceroute)

# Allow necessary ICMPv6 messages for PMTUD and Neighbor Discovery Protocol (NDP)
pass in inet6 proto icmp6 icmp6-type 128 no state   # Echo Request (ping)
pass in inet6 proto icmp6 icmp6-type 2 no state     # Packet Too Big (PMTUD)
pass in inet6 proto icmp6 icmp6-type 3 no state     # Time Exceeded (traceroute)
pass in inet6 proto icmp6 icmp6-type 133 no state   # NDP Router Solicitation
pass in inet6 proto icmp6 icmp6-type 134 no state   # NDP Router Advertisement
pass in inet6 proto icmp6 icmp6-type 135 no state   # NDP Neighbor Solicitation
pass in inet6 proto icmp6 icmp6-type 136 no state   # NDP Neighbor Advertisement

# Optionally allow incoming SSH traffic on port 22
#pass in proto tcp from any to any port 22 keep state

# Allow all outgoing traffic and keep state for reply packets
pass out keep state
EOF

    # Backup /etc/pf.conf if it hasn't been backed up yet
    if [ ! -f "$BACKUP_FILE" ]; then
        echo "Backing up $PF_CONF to $BACKUP_FILE..."
        cp "$PF_CONF" "$BACKUP_FILE"
    fi

    # Check if the custom anchor is already included in /etc/pf.conf
    if ! grep -q "anchor \"$ANCHOR_NAME\"" "$PF_CONF"; then
        echo "Adding custom anchor to $PF_CONF..."
        tee -a "$PF_CONF" >/dev/null <<EOF
# Load custom security rules from '$ANCHOR_NAME' anchor
anchor "$ANCHOR_NAME"
load anchor "$ANCHOR_NAME" from "$ANCHOR_FILE"
EOF
    else
        echo "Custom anchor is already present in $PF_CONF."
    fi

    # Apply the custom rules to the anchor without flushing all rules
    echo "Applying custom pf rules to the '$ANCHOR_NAME' anchor..."
    pfctl -a "$ANCHOR_NAME" -f "$ANCHOR_FILE"
    pfctl -e || true # Ignore errors if the rules are already applied

    # Verify the rules are applied
    echo "Verifying active pf rules for '$ANCHOR_NAME'..."
    pfctl -a "$ANCHOR_NAME" -sr

    # Confirm the status of pf
    echo "Checking pf status..."
    pfctl -si

    echo "macOS pf security hardening complete!"
}

# Function to uninstall the custom rules
uninstall_pf_rules() {
    echo "Uninstalling custom pf rules..."

    # Remove the anchor reference from /etc/pf.conf if it exists
    if grep -q "anchor \"$ANCHOR_NAME\"" "$PF_CONF"; then
        echo "Removing custom anchor from $PF_CONF..."
        # Use a single sed command with multiple -e options for precise line deletion
        sed -i.bak -e "/# Load custom security rules from '$ANCHOR_NAME' anchor/d" \
            -e "/anchor \"$ANCHOR_NAME\"/d" \
            -e "/load anchor \"$ANCHOR_NAME\" from .*/d" "$PF_CONF"
        echo "Removed custom anchor references from $PF_CONF."
    else
        echo "Custom anchor not found in $PF_CONF."
    fi

    # Remove the custom anchor file
    if [ -f "$ANCHOR_FILE" ]; then
        echo "Deleting $ANCHOR_FILE..."
        rm -f "$ANCHOR_FILE"
    else
        echo "No custom anchor file found at $ANCHOR_FILE."
    fi

    # Reload the original or updated pf configuration
    echo "Reloading pf configuration to apply changes..."
    pfctl -f "$PF_CONF"
    pfctl -e || true # Ignore errors if the rules are already applied

    echo "Uninstallation complete. The pf firewall has been restored."
}

# Main function to handle user input and flow of the script
main() {
    # Detect if the custom rules are already installed
    if is_installed; then
        echo "Custom pf rules are already installed."
        DEFAULT_ACTION="reinstall"
    else
        echo "No existing installation of custom pf rules detected."
        DEFAULT_ACTION="install"
    fi

    # Get the action from the user if not provided as an argument
    ACTION="${1:-}"
    if [ -z "$ACTION" ]; then
        read -r -p "Please specify an action (install, reinstall, uninstall) [Default: $DEFAULT_ACTION]: " ACTION
        ACTION="${ACTION:-$DEFAULT_ACTION}"
    fi

    # Handle the action
    case "$ACTION" in
    install)
        install_pf_rules
        ;;
    reinstall)
        echo "Reinstalling custom pf rules..."
        uninstall_pf_rules
        install_pf_rules
        ;;
    uninstall)
        uninstall_pf_rules
        ;;
    *)
        echo "Invalid action: $ACTION"
        echo "Usage: $0 {install|reinstall|uninstall}"
        exit 1
        ;;
    esac
}

# Run the main function with all arguments
main "$@"

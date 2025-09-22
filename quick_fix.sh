#!/bin/bash

# ArgusPi Quick Fix - Robust GUI Service Update
# This script fixes existing installations to work with modern Raspberry Pi OS

set -e

echo "==========================================="
echo "ArgusPi Quick Fix for Modern Raspberry Pi"
echo "==========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Stop the service if running
echo "Stopping ArgusPi service..."
systemctl stop arguspi.service 2>/dev/null || true

# Detect desktop user
DESKTOP_USER=$(who | grep -E "(console|:0)" | head -n1 | awk '{print $1}' 2>/dev/null)
if [[ -z "$DESKTOP_USER" ]]; then
    DESKTOP_USER=$(ls -la /home | grep -v "^total" | tail -n1 | awk '{print $9}' 2>/dev/null)
fi

if [[ -z "$DESKTOP_USER" || "$DESKTOP_USER" == "." || "$DESKTOP_USER" == ".." ]]; then
    echo "Could not detect desktop user. Assuming 'pi'"
    DESKTOP_USER="pi"
fi

USER_ID=$(id -u $DESKTOP_USER 2>/dev/null || echo "1000")
HOME_DIR=$(eval echo ~$DESKTOP_USER)

echo "Detected desktop user: $DESKTOP_USER"
echo "User home directory: $HOME_DIR"

# Create improved service file
echo "Creating robust service configuration..."

cat > /etc/systemd/system/arguspi.service << EOF
[Unit]
Description=ArgusPi USB Security Scanner with GUI
After=graphical-session.target display-manager.service
Wants=graphical-session.target display-manager.service

[Service]
Type=simple
User=root
Group=root
# Robust wait for display server - works with Xorg, X11, labwc, and Wayland
ExecStartPre=/bin/bash -c 'timeout=60; while [ \$timeout -gt 0 ] && [ ! -S /tmp/.X11-unix/X0 ]; do sleep 1; timeout=\$((timeout-1)); done'
# Wait for desktop session to start - handles multiple desktop environments  
ExecStartPre=/bin/bash -c 'timeout=30; while [ \$timeout -gt 0 ] && ! pgrep -f "lxsession|gnome-session|xfce4-session|labwc|startlxde" > /dev/null; do sleep 1; timeout=\$((timeout-1)); done'
Environment=DISPLAY=:0
Environment=XDG_RUNTIME_DIR=/run/user/$USER_ID
Environment=XAUTHORITY=$HOME_DIR/.Xauthority
Environment=HOME=$HOME_DIR
# Allow X11 forwarding from root - works with both X11 and XWayland
ExecStartPre=/bin/bash -c 'su $DESKTOP_USER -c "xhost +local:root 2>/dev/null || true"'
ExecStart=/usr/bin/python3 /usr/local/bin/arguspi_scan_station.py
Restart=always
RestartSec=10
TimeoutStartSec=120

[Install]
WantedBy=graphical.target
EOF

echo "✓ Service file updated with robust configuration"

# Reload systemd and enable service
echo "Reloading systemd configuration..."
systemctl daemon-reload
systemctl enable arguspi.service

# Test the configuration
echo "Starting ArgusPi service..."
systemctl start arguspi.service

# Check status
sleep 3
if systemctl is-active --quiet arguspi.service; then
    echo "✓ ArgusPi service started successfully!"
    echo ""
    echo "Service status:"
    systemctl status arguspi.service --no-pager -l
else
    echo "⚠ Service may still be starting. Check status with:"
    echo "  sudo systemctl status arguspi.service"
    echo "  sudo journalctl -u arguspi.service -f"
fi

echo ""
echo "==========================================="
echo "✓ ArgusPi Quick Fix Complete!"
echo ""
echo "The service now supports:"
echo "• Traditional Xorg (older Pi OS)"
echo "• Modern Wayland/labwc (newer Pi OS)"  
echo "• Robust timeout handling"
echo "• Better error handling"
echo ""
echo "Monitor service: sudo journalctl -u arguspi.service -f"
echo "==========================================="
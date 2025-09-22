#!/bin/bash
"""
ArgusPi Service Fix Script
=========================

This script fixes the GUI startup issue by updating the systemd service 
to properly wait for the desktop session and set correct environment variables.
"""

# Stop the current service
sudo systemctl stop arguspi

# Get the actual desktop user (not root)
DESKTOP_USER=$(who | grep "(:0)" | awk '{print $1}' | head -1)
if [ -z "$DESKTOP_USER" ]; then
    # Fallback to detect user from /home
    DESKTOP_USER=$(ls /home | head -1)
fi

if [ -z "$DESKTOP_USER" ]; then
    DESKTOP_USER="silverday"  # Your username as fallback
fi

echo "Detected desktop user: $DESKTOP_USER"

# Get user details
USER_HOME=$(eval echo "~$DESKTOP_USER")
USER_UID=$(id -u $DESKTOP_USER)

echo "User home: $USER_HOME"
echo "User UID: $USER_UID"

# Create improved systemd service
sudo tee /etc/systemd/system/arguspi.service << EOF
[Unit]
Description=ArgusPi USB Security Scanner with GUI
After=graphical-session.target
Wants=graphical-session.target
# Wait for desktop session to be fully ready
After=display-manager.service
Wants=display-manager.service

[Service]
Type=simple
User=root
Group=root
# Wait for X11 to be available
ExecStartPre=/bin/bash -c 'while ! pgrep -x "Xorg\\|X" > /dev/null; do sleep 1; done'
# Wait for desktop session to start
ExecStartPre=/bin/bash -c 'while ! pgrep -f "lxsession\\|gnome-session\\|xfce4-session" > /dev/null; do sleep 1; done'
# Set GUI environment variables for X11 access
Environment=DISPLAY=:0
Environment=XDG_RUNTIME_DIR=/run/user/$USER_UID
Environment=XAUTHORITY=$USER_HOME/.Xauthority
Environment=HOME=$USER_HOME
# Allow X11 forwarding from root
ExecStartPre=/bin/bash -c 'su $DESKTOP_USER -c "xhost +local:root" || true'
ExecStart=/usr/bin/python3 /usr/local/bin/arguspi_scan_station.py
Restart=always
RestartSec=10
# Give more time for desktop to be ready
TimeoutStartSec=60

[Install]
WantedBy=graphical.target
EOF

# Replace $USER_UID and $DESKTOP_USER in the service file
sudo sed -i "s/\$USER_UID/$USER_UID/g" /etc/systemd/system/arguspi.service
sudo sed -i "s/\$DESKTOP_USER/$DESKTOP_USER/g" /etc/systemd/system/arguspi.service
sudo sed -i "s|\$USER_HOME|$USER_HOME|g" /etc/systemd/system/arguspi.service

# Reload systemd and start service
sudo systemctl daemon-reload
sudo systemctl enable arguspi
sudo systemctl start arguspi

echo ""
echo "✅ ArgusPi service updated with desktop session synchronization"
echo ""
echo "🔍 Check status with:"
echo "   sudo systemctl status arguspi"
echo ""
echo "📋 View logs with:"  
echo "   sudo journalctl -u arguspi -f"
echo ""
echo "🔄 If issues persist, reboot and check again:"
echo "   sudo reboot"
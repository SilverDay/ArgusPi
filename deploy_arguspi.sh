#!/bin/bash

# ArgusPi Complete Deployment Script
# This script deploys the complete ArgusPi system with all fixes and diagnostics

set -e  # Exit on any error

echo "==========================================="
echo "ArgusPi Complete Deployment Script"
echo "==========================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "This script should NOT be run as root for safety."
   echo "It will use sudo when needed."
   exit 1
fi

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if files exist
required_files=("arguspi_setup.py" "arguspi_scan_station.py" "gui_diagnostic.py")
for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        print_error "Required file $file not found!"
        exit 1
    fi
done

print_status "All required files found"

# Update system
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
print_status "Installing Python dependencies..."
sudo apt install -y python3-pip python3-tk python3-dev python3-setuptools
pip3 install --user psutil requests

# Install system utilities
print_status "Installing system utilities..."
sudo apt install -y usbutils lsof clamav clamav-daemon systemd git

# Update ClamAV database
print_status "Updating ClamAV virus database..."
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam

# Install X11 utilities for GUI support
print_status "Installing X11 utilities..."
sudo apt install -y x11-xserver-utils xauth

# Copy files to system locations
print_status "Installing ArgusPi files..."
sudo cp arguspi_scan_station.py /usr/local/bin/
sudo cp gui_diagnostic.py /usr/local/bin/
sudo chmod +x /usr/local/bin/arguspi_scan_station.py
sudo chmod +x /usr/local/bin/gui_diagnostic.py

# Run the setup script
print_status "Running ArgusPi setup..."
sudo python3 arguspi_setup.py

# Check display configuration
print_status "Checking display configuration..."
config_file="/boot/firmware/config.txt"
if [[ ! -f "$config_file" ]]; then
    config_file="/boot/config.txt"
fi

if [[ -f "$config_file" ]]; then
    print_status "Display config file: $config_file"
    if ! grep -q "display_rotate=2" "$config_file"; then
        print_warning "Display rotation not set. Adding display_rotate=2 for upside-down screens..."
        echo "display_rotate=2" | sudo tee -a "$config_file"
        print_success "Display rotation configured"
    else
        print_success "Display rotation already configured"
    fi
else
    print_warning "Could not find display config file"
fi

# Enable and start the service
print_status "Configuring ArgusPi service..."
sudo systemctl daemon-reload
sudo systemctl enable arguspi.service

# Run diagnostics
print_status "Running GUI diagnostics..."
python3 /usr/local/bin/gui_diagnostic.py

# Check service status
print_status "Checking service configuration..."
sudo systemctl status arguspi.service --no-pager || true

print_success "ArgusPi deployment completed!"
echo
echo "==========================================="
echo "Next Steps:"
echo "==========================================="
echo "1. If display rotation was added, reboot to apply: sudo reboot"
echo "2. Start the service: sudo systemctl start arguspi.service"
echo "3. Monitor the service: sudo journalctl -u arguspi.service -f"
echo "4. Check GUI status: python3 /usr/local/bin/gui_diagnostic.py"
echo
echo "If you encounter GUI issues, run the fix:"
echo "bash fix_gui_service.sh"
echo
print_success "Deployment script finished!"
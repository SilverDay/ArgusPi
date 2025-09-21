# ArgusPi Troubleshooting Guide

This guide helps you resolve common issues with ArgusPi installation and operation.

## 🔍 Quick Diagnostics

### Check ArgusPi Status

```bash
# Check service status
sudo systemctl status arguspi

# Check configuration
sudo python3 -c "import json; print(json.load(open('/etc/arguspi/config.json')))"

# View recent logs
sudo journalctl -u arguspi -n 50
```

## 🐛 Common Issues

### ArgusPi Service Won't Start

**Symptoms:** Service fails to start or crashes immediately

**Diagnosis:**

```bash
# Check service status
sudo systemctl status arguspi

# Check detailed logs
sudo journalctl -u arguspi -f
```

**Solutions:**

1. Verify configuration file exists: `ls -la /etc/arguspi/config.json`
2. Validate JSON syntax: `python3 -c "import json; json.load(open('/etc/arguspi/config.json'))"`
3. Check Python dependencies: `pip3 list | grep -E "(requests|pyudev)"`

### USB Devices Not Detected

**Symptoms:** USB insertion doesn't trigger scanning

**Diagnosis:**

```bash
# Check udev rules
ls -la /etc/udev/rules.d/90-arguspi-readonly.rules

# Monitor USB events
sudo udevadm monitor --property
```

**Solutions:**

```bash
# Reload udev rules
sudo udevadm control --reload

# Restart udev service
sudo systemctl restart systemd-udevd

# Test manual detection
lsblk
```

### VirusTotal API Errors

**Symptoms:** API key rejection or quota errors

**Diagnosis:**

```bash
# Test API key manually
curl -H "x-apikey: YOUR_API_KEY" https://www.virustotal.com/api/v3/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Solutions:**

1. Verify API key in configuration file
2. Check API quota: Look for "quota" or "limit" in logs
3. Consider enabling ClamAV to reduce API calls

## 🖥️ GUI Issues

### GUI Not Displaying After Reboot

**Symptoms:** ArgusPi GUI doesn't appear on screen after reboot

**Step-by-Step Diagnosis:**

```bash
# Step 1: Check what user account was detected during setup
whoami
echo $HOME

# Step 2: Check if desktop autostart entry exists for YOUR user
ls -la $HOME/.config/autostart/arguspi.desktop
cat $HOME/.config/autostart/arguspi.desktop

# Step 3: Check if autologin is enabled for your user
sudo raspi-config nonint get_boot_behaviour
# Should return 4 for Desktop Autologin

# Step 4: Test GUI manually to isolate the issue
python3 /usr/local/bin/arguspi_scan_station.py

# Step 5: Check for running processes
ps aux | grep arguspi

# Step 6: Check desktop environment
echo $DESKTOP_SESSION
echo $XDG_CURRENT_DESKTOP

# Step 7: Test basic Tkinter functionality
python3 -c "import tkinter; root = tkinter.Tk(); root.title('Test GUI'); root.after(3000, root.quit); root.mainloop()"

# Step 8: Check system logs for errors
journalctl --user -f | grep -i arguspi
```

### Common GUI Solutions

**If autostart file is missing or in wrong location:**

```bash
# Find your actual username and home directory
USERNAME=$(whoami)
HOMEDIR=$HOME

# Recreate the desktop autostart entry for YOUR user
mkdir -p $HOME/.config/autostart
cat > $HOME/.config/autostart/arguspi.desktop << EOF
[Desktop Entry]
Type=Application
Name=ArgusPi USB Security Scanner
Exec=python3 /usr/local/bin/arguspi_scan_station.py
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Comment=ArgusPi USB Security Scanner GUI
EOF

# Fix ownership for your user
sudo chown -R $USERNAME:$USERNAME $HOME/.config
```

**If GUI starts manually but not on boot:**

```bash
# Add delay to autostart (some systems need time for desktop to load)
sed -i 's/Exec=python3/Exec=sh -c "sleep 10 && python3"/' $HOME/.config/autostart/arguspi.desktop

# Alternative: Use systemd user service instead
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/arguspi.service << EOF
[Unit]
Description=ArgusPi GUI
After=graphical-session.target

[Service]
Type=simple
ExecStart=python3 /usr/local/bin/arguspi_scan_station.py
Restart=always
Environment=DISPLAY=:0

[Install]
WantedBy=default.target
EOF

# Enable user service
systemctl --user enable arguspi.service
systemctl --user start arguspi.service
```

**If using Wayland instead of X11:**

```bash
# Check display server
echo $XDG_SESSION_TYPE

# If Wayland, switch to X11 or set environment
# Edit autostart file to include Wayland support
sed -i 's/Exec=python3/Exec=env GDK_BACKEND=x11 python3/' $HOME/.config/autostart/arguspi.desktop
```

### Configure Autologin for GUI

**Required for automatic GUI startup:**

```bash
# Method 1: Using raspi-config (recommended)
sudo raspi-config
# Navigate to: System Options → Boot / Auto Login → Desktop Autologin

# Method 2: Direct systemd configuration (if raspi-config unavailable)
USERNAME=$(whoami)
sudo mkdir -p /etc/systemd/system/getty@tty1.service.d
sudo tee /etc/systemd/system/getty@tty1.service.d/autologin.conf << EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin $USERNAME --noclear %I \$TERM
EOF
sudo systemctl daemon-reload
sudo systemctl enable getty@tty1.service
```

## ⚡ Performance Issues

### Scanning is Very Slow

**Symptoms:** USB scans take hours instead of minutes

**Root Cause:** Not using ClamAV pre-filtering

**Solution:**

```bash
# Quick fix: Enable ClamAV
sudo apt-get install clamav clamav-daemon
sudo freshclam
# Edit config: "use_clamav": true
sudo systemctl restart arguspi
```

**Performance Comparison:**

- **Without ClamAV**: Every file sent to VirusTotal (20s per file)
- **With ClamAV**: Only suspicious files sent to VirusTotal

### Out of VirusTotal API Quota

**Symptoms:** API quota exceeded messages in logs

**Diagnosis:**

```bash
# Check current usage in logs
sudo tail -f /var/log/arguspi.log | grep -i "quota\|limit"
```

**Solutions:**

1. Enable ClamAV to reduce API calls
2. Upgrade VirusTotal plan
3. Increase request interval in configuration

## 🔧 Update Issues

### GUI Doesn't Start After Update

**Symptoms:** GUI worked before update but not after

**Diagnosis and Solutions:**

```bash
# 1. Verify new desktop autostart was created
cat $HOME/.config/autostart/arguspi.desktop

# 2. Check if old systemd service is interfering
sudo systemctl status arguspi
sudo systemctl stop arguspi 2>/dev/null || true
sudo systemctl disable arguspi 2>/dev/null || true

# 3. Test manual startup
python3 /usr/local/bin/arguspi_scan_station.py

# 4. If manual works but autostart doesn't, try user systemd service
systemctl --user enable ~/.config/systemd/user/arguspi.service 2>/dev/null || echo "User service not found - using desktop autostart"
```

## 📊 Log Analysis

### Log Locations

- **Service logs**: `sudo journalctl -u arguspi`
- **Scan results**: `/var/log/arguspi.log`
- **System logs**: `/var/log/syslog`

### Understanding Scan Results

**Status Indicators:**

| Status       | LED Color      | GUI Color | Description             |
| ------------ | -------------- | --------- | ----------------------- |
| **Waiting**  | Blue           | Blue      | Ready for USB insertion |
| **Scanning** | Yellow         | Yellow    | Analyzing files         |
| **Clean**    | Green          | Green     | No threats detected     |
| **Infected** | Red (solid)    | Red       | Malware found           |
| **Error**    | Red (blinking) | Red       | Scan error occurred     |

**Log Format Examples:**

```
2025-09-20 14:30:15 [ArgusPi-INFO] - ArgusPi detected USB device /dev/sdb1
2025-09-20 14:30:16 [ArgusPi-INFO] - Mounted /dev/sdb1 at /mnt/arguspi/sdb1
2025-09-20 14:30:20 [ArgusPi-INFO] - CLEAN | a1b2c3d4... | document.pdf | details: {...}
```

## 🆘 Getting Help

### Before Requesting Support

Please gather the following information:

```bash
# System information
uname -a
lsb_release -a

# ArgusPi status
sudo systemctl status arguspi
sudo journalctl -u arguspi -n 20

# Configuration check
cat /etc/arguspi/config.json

# USB detection test
lsblk
```

### Support Channels

- **GitHub Issues**: [ArgusPi Issues](https://github.com/silverday/arguspi/issues)
- **GitHub Discussions**: [ArgusPi Discussions](https://github.com/silverday/arguspi/discussions)
- **Security Issues**: Report privately to security@yourproject.com

### Useful Commands for Support

```bash
# Generate support bundle
tar -czf arguspi-support-$(date +%Y%m%d).tar.gz \
  /etc/arguspi/config.json \
  /var/log/arguspi.log \
  ~/.config/autostart/arguspi.desktop \
  <(sudo systemctl status arguspi) \
  <(sudo journalctl -u arguspi -n 50)
```

This creates a support bundle you can attach to issue reports.

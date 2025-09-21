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

### "Device Already Mounted" Error

**Symptoms:** Error popup saying "/dev/sda1 is already mounted at /mnt/arguspi/sda1" when inserting USB

**Root Cause:** The desktop environment auto-mounts USB devices before ArgusPi can mount them, causing a conflict.

**Solutions:**

```bash
# Method 1: Restart ArgusPi service to apply the latest mounting logic
sudo systemctl restart arguspi

# Method 2: Check what's currently mounted
mount | grep /dev/sd
# or
lsblk

# Method 3: Manually unmount conflicting mounts if needed
sudo umount /dev/sda1  # Replace with your device

# Method 4: Disable desktop auto-mounting (optional, for dedicated kiosk)
# Create a rule to prevent desktop auto-mounting
sudo tee /etc/udev/rules.d/99-no-automount.rules << EOF
# Disable automounting for all block devices
SUBSYSTEM=="block", ENV{UDISKS_IGNORE}="1"
EOF

# Reload udev rules
sudo udevadm control --reload-rules

# Note: This will disable ALL USB auto-mounting, including for user access
```

**Technical Details:**

The updated ArgusPi code now:
1. Checks if a device is already mounted before attempting to mount it
2. Uses existing mounts when available instead of creating conflicts
3. Only unmounts devices that ArgusPi mounted itself
4. Leaves system/desktop mounts intact after scanning

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
Exec=sudo python3 /usr/local/bin/arguspi_scan_station.py
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Comment=ArgusPi USB Security Scanner GUI
EOF

# Fix ownership for your user
sudo chown -R $USERNAME:$USERNAME $HOME/.config
```

**If GUI requires sudo and desktop autostart doesn't work:**

Desktop autostart entries with `sudo` don't work reliably because they can't handle password prompts during boot. The solution is to disable the desktop autostart and use the systemd service instead.

```bash
# 1. Disable desktop autostart (since it conflicts with sudo requirements)
rm -f $HOME/.config/autostart/arguspi.desktop

# 2. Make sure the systemd service is enabled and running
sudo systemctl enable arguspi
sudo systemctl start arguspi

# 3. Check if the service is working
sudo systemctl status arguspi
sudo journalctl -u arguspi -f

# 4. The GUI should now appear automatically after reboot via the systemd service
```

**Fix for "Authorization required, but no authorization protocol specified" error:**

This error occurs when the systemd service tries to access the X11 display server but lacks proper authorization. The fix is to update the service configuration:

```bash
# Stop the current service
sudo systemctl stop arguspi

# Get your user info
USERNAME=$(whoami)
HOMEDIR=$HOME
UID=$(id -u $USERNAME)

# Create the corrected service file
sudo tee /etc/systemd/system/arguspi.service << EOF
[Unit]
Description=ArgusPi USB Security Scanner with GUI
After=graphical.target
Wants=graphical.target

[Service]
Type=simple
User=root
Group=root
Environment=DISPLAY=:0
Environment=XDG_RUNTIME_DIR=/run/user/$UID
Environment=XAUTHORITY=$HOMEDIR/.Xauthority
Environment=HOME=$HOMEDIR
ExecStart=/usr/bin/python3 /usr/local/bin/arguspi_scan_station.py
Restart=always
RestartSec=5

[Install]
WantedBy=graphical.target
EOF

# Reload and restart the service
sudo systemctl daemon-reload
sudo systemctl start arguspi

# Check the status - should now work without X11 authorization errors
sudo systemctl status arguspi
```

**Alternative: Use systemd user service with proper environment:**

If you prefer a user service approach:

```bash
# 1. Remove desktop autostart
rm -f $HOME/.config/autostart/arguspi.desktop

# 2. Create user systemd service
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/arguspi-gui.service << EOF
[Unit]
Description=ArgusPi GUI
After=graphical-session.target
Wants=graphical-session.target

[Service]
Type=simple
ExecStart=/usr/bin/sudo /usr/bin/python3 /usr/local/bin/arguspi_scan_station.py
Restart=always
RestartSec=10
Environment=DISPLAY=:0
Environment=XDG_RUNTIME_DIR=/run/user/1000

[Install]
WantedBy=default.target
EOF

# 3. Enable and start the user service
systemctl --user daemon-reload
systemctl --user enable arguspi-gui.service
systemctl --user start arguspi-gui.service

# 4. Check status
systemctl --user status arguspi-gui.service
```

**If using Wayland instead of X11:**

```bash
# Check display server
echo $XDG_SESSION_TYPE

# If Wayland, switch to X11 or set environment
# Edit autostart file to include Wayland support
sed -i 's/Exec=python3/Exec=env GDK_BACKEND=x11 python3/' $HOME/.config/autostart/arguspi.desktop
```

### GUI Window Not Fullscreen

**Symptoms:** ArgusPi GUI appears in a small window instead of fullscreen

**Solutions:**

```bash
# Method 1: Restart the service (applies latest window configuration)
sudo systemctl restart arguspi

# Method 2: Test fullscreen manually to check if it works
python3 -c "
import tkinter as tk
root = tk.Tk()
root.title('Fullscreen Test')
try:
    root.attributes('-fullscreen', True)
    print('✓ Fullscreen supported')
except Exception as e:
    print(f'⚠ Fullscreen not supported: {e}')
root.after(3000, root.quit)
root.mainloop()
"

# Method 3: Check display resolution and configuration
xrandr
# Should show your display resolution

# Method 4: If using VNC or remote desktop
# VNC/Remote sessions may not support fullscreen properly
# Try running directly on the Pi's display
```

**For persistent windowed mode issues:**

```bash
# Check what window manager is running
ps aux | grep -E "openbox|lxde|xfce|gnome"

# Some window managers may override fullscreen requests
# Try forcing window geometry instead
# (This requires updating the Python code to use explicit geometry)
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

**Symptoms:** USB scans take hours instead of minutes, even with ClamAV enabled

**Root Causes and Solutions:**

**1. ClamAV not properly installed or daemon not running:**

```bash
# Check if ClamAV daemon is running
sudo systemctl status clamav-daemon
sudo systemctl status clamav-freshclam

# If clamav-daemon is not found, install the complete ClamAV package:
sudo apt update
sudo apt install -y clamav clamav-daemon clamav-freshclam

# Start and enable ClamAV services
sudo systemctl enable clamav-daemon
sudo systemctl enable clamav-freshclam
sudo systemctl start clamav-freshclam
sudo systemctl start clamav-daemon

# Check ClamAV configuration in ArgusPi
cat /etc/arguspi/config.json | grep -i clam

# Test ClamAV manually
clamscan --version
echo "test" > /tmp/testfile
clamscan /tmp/testfile
rm /tmp/testfile
```

**2. ClamAV database not updated:**

```bash
# Update ClamAV database
sudo freshclam

# Check database age
sudo find /var/lib/clamav -name "*.cvd" -o -name "*.cld" | xargs ls -la

# Restart ClamAV daemon after update
sudo systemctl restart clamav-daemon
sudo systemctl restart arguspi
```

**3. ArgusPi configuration issue:**

```bash
# Verify ClamAV is enabled in config
python3 -c "
import json
config = json.load(open('/etc/arguspi/config.json'))
print(f'use_clamav: {config.get(\"use_clamav\", \"NOT SET\")}')
print(f'clamav_timeout: {config.get(\"clamav_timeout\", \"NOT SET\")}')
"

# If use_clamav is false or missing, fix it:
sudo python3 -c "
import json
with open('/etc/arguspi/config.json', 'r') as f:
    config = json.load(f)
config['use_clamav'] = True
config['clamav_timeout'] = 60  # 60 seconds timeout
with open('/etc/arguspi/config.json', 'w') as f:
    json.dump(config, f, indent=2)
print('✓ ClamAV enabled in config')
"

# Restart ArgusPi after config change
sudo systemctl restart arguspi
```

**4. Still sending all files to VirusTotal:**

Check the logs to see if ClamAV is actually pre-filtering:

```bash
# Monitor scanning in real-time
sudo tail -f /var/log/arguspi.log

# Look for ClamAV activity patterns:
# - Should see "ClamAV scan started" messages
# - Should see "CLEAN" results from ClamAV before VirusTotal
# - Should see fewer VirusTotal API calls

# Check recent ClamAV activity
sudo journalctl -u arguspi -n 100 | grep -i clam
```

**5. Large files or many files:**

```bash
# Check what's being scanned
sudo tail -f /var/log/arguspi.log | grep -E "Scanning|files found"

# If too many files, check scan scope
lsblk  # Insert USB and check size
# Consider excluding certain file types if appropriate
```

**Performance Comparison:**

- **Without ClamAV**: Every file sent to VirusTotal (20s per file)
- **With ClamAV working properly**: Only suspicious files sent to VirusTotal
- **Expected speed with ClamAV**: ~10 minutes for 1000 files vs ~5.5 hours without

**Quick ClamAV Test:**

```bash
# Test ClamAV performance on a sample file
sudo python3 -c "
import subprocess
import time
start = time.time()
result = subprocess.run(['clamscan', '/usr/local/bin/arguspi_scan_station.py'],
                       capture_output=True, text=True)
print(f'ClamAV scan took {time.time() - start:.2f} seconds')
print(f'Result: {result.returncode}')
print(result.stdout)
"
```

If ClamAV takes more than a few seconds per file, there might be a performance issue with the ClamAV installation itself.

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

# ArgusPi Installation Guide

This guide provides detailed installation instructions for setting up ArgusPi on your Raspberry Pi.

## 🛠️ System Requirements

### Hardware Requirements

- **Raspberry Pi 5** (8GB RAM recommended, 4GB minimum)
- **MicroSD card** (32GB+ Class 10/A2 recommended for better performance)
- **Optional: 7-inch touchscreen** for GUI display
- **Optional: RGB LED** for status indication

> **💡 Why Pi 5?** File hashing, ClamAV scanning, and GUI operations benefit significantly from the Pi 5's improved CPU, memory bandwidth, and I/O performance.

### Software Requirements

- **Raspberry Pi OS** (Bookworm or newer)
- **Python 3.9+** with pip
- **Root access** for installation
- **Optional: Internet connection** for VirusTotal API access _(works offline too!)_

## 🚀 Installation Steps

### Step 1: Download ArgusPi

```bash
git clone https://github.com/silverday/arguspi.git
cd arguspi
```

### Step 2: Get VirusTotal API Key (Optional)

**For Online Mode:**

1. Visit [VirusTotal](https://www.virustotal.com/)
2. Create a free account
3. Go to your profile and copy your API key

**For Offline/Air-Gapped Mode:**
Skip this step - ArgusPi will run in offline mode using only local ClamAV scanning.

### Step 3: Run Setup Script

```bash
sudo python3 arguspi_setup.py
```

The setup script will:

- ✅ Validate your VirusTotal API key
- ✅ Configure system paths and settings
- ✅ Install required packages (handles modern Python environments automatically)
- ✅ Create GUI desktop autostart entry
- ✅ Create systemd service with proper GUI support
- ✅ Set up USB auto-detection rules

### Step 4: Enable Desktop Autologin (Required for GUI)

For the ArgusPi GUI to start automatically, you must manually enable desktop autologin:

```bash
# Run Raspberry Pi configuration tool
sudo raspi-config
```

Then navigate to:

1. **System Options** → **Boot / Auto Login** → **Desktop Autologin**
2. Select your user account
3. Exit raspi-config and reboot

### Step 5: Reboot and Test

```bash
# Reboot to activate autologin and GUI settings
sudo reboot
```

After reboot:

1. ArgusPi GUI should appear automatically on screen
2. Insert a USB device to test scanning
3. Watch the GUI respond with status updates

## 📋 Configuration Options

During setup, you can configure:

| Option                 | Description                            | Default           | Performance Impact     |
| ---------------------- | -------------------------------------- | ----------------- | ---------------------- |
| **Station Name**       | Unique identifier for this station     | `arguspi-station` | SIEM event correlation |
| **API Key**            | VirusTotal API key for cloud scanning  | _Optional_        | Enables cloud analysis |
| **Mount Path**         | Directory for mounting USB devices     | `/mnt/arguspi`    | N/A                    |
| **Request Interval**   | Seconds between VirusTotal requests    | `20` (free tier)  | 4 requests/min max     |
| **ClamAV Integration** | Enable local antivirus scanning        | `Yes`             | **🚀 HUGE speedup!**   |
| **SIEM Integration**   | Send events to security monitoring     | `No`              | Enterprise visibility  |
| **RGB LED**            | GPIO pins for status LED               | `17,27,22`        | N/A                    |
| **GUI Interface**      | Enable touchscreen interface           | `Yes`             | N/A                    |
| **Screen Orientation** | Display rotation (0°, 90°, 180°, 270°) | `0°` (Normal)     | Touchscreen layout     |

> **💡 Pro Tip**: For best results, enable ClamAV! It provides fast local scanning whether you're online or offline.

## 🔧 Manual Configuration

### Configuration File Location

Edit `/etc/arguspi/config.json` for advanced configuration:

### Online Mode Configuration

```json
{
  "station_name": "arguspi-station",
  "api_key": "your_virustotal_api_key_here",
  "mount_base": "/mnt/arguspi",
  "request_interval": 20,
  "use_clamav": true,
  "use_led": true,
  "led_pins": { "red": 17, "green": 27, "blue": 22 },
  "use_gui": true,
  "siem_enabled": false
}
```

### Offline/Air-Gapped Mode Configuration

```json
{
  "station_name": "secure-lab-entrance",
  "api_key": "",
  "mount_base": "/mnt/arguspi",
  "request_interval": 20,
  "use_clamav": true,
  "use_led": true,
  "led_pins": { "red": 17, "green": 27, "blue": 22 },
  "use_gui": true,
  "siem_enabled": false
}
```

### Enterprise SIEM Integration

**Syslog Configuration:**

```json
{
  "station_name": "reception-desk",
  "api_key": "your_virustotal_api_key_here",
  "mount_base": "/mnt/arguspi",
  "request_interval": 20,
  "use_clamav": true,
  "use_led": true,
  "led_pins": { "red": 17, "green": 27, "blue": 22 },
  "use_gui": true,
  "siem_enabled": true,
  "siem_type": "syslog",
  "siem_server": "splunk-indexer.company.com",
  "siem_port": 514,
  "siem_facility": "local0"
}
```

**HTTP Webhook Configuration:**

```json
{
  "station_name": "security-checkpoint-1",
  "api_key": "your_virustotal_api_key_here",
  "mount_base": "/mnt/arguspi",
  "request_interval": 20,
  "use_clamav": true,
  "use_led": true,
  "led_pins": { "red": 17, "green": 27, "blue": 22 },
  "use_gui": true,
  "siem_enabled": true,
  "siem_type": "webhook",
  "siem_webhook_url": "https://your-siem.com/api/events",
  "siem_headers": {
    "Authorization": "Bearer your-api-token"
  }
}
```

> **🔒 Air-Gapped Security**: When `api_key` is empty, ArgusPi runs in offline mode with local ClamAV scanning only - perfect for secure environments!

## 🔄 Service Management

ArgusPi runs as a systemd service:

```bash
# Check status
sudo systemctl status arguspi

# View logs
sudo journalctl -u arguspi -f

# Restart service
sudo systemctl restart arguspi

# Stop service
sudo systemctl stop arguspi

# Disable service
sudo systemctl disable arguspi
```

## ⚡ Performance Optimization

### Enable ClamAV for Better Performance

```bash
# Install ClamAV
sudo apt-get update
sudo apt-get install clamav clamav-daemon

# Update virus definitions
sudo freshclam

# Enable in ArgusPi config
sudo nano /etc/arguspi/config.json
# Set: "use_clamav": true

# Restart service
sudo systemctl restart arguspi
```

### Performance Comparison

| USB Contents     | Offline Mode    | Online (no ClamAV) | Online + ClamAV |
| ---------------- | --------------- | ------------------ | --------------- |
| 100 clean files  | **~2 minutes**  | ~33 minutes        | **~2 minutes**  |
| 500 clean files  | **~5 minutes**  | ~2.8 hours         | **~5 minutes**  |
| 1000 clean files | **~10 minutes** | ~5.5 hours         | **~10 minutes** |

> **🚀 Speed Champions**: Offline mode and Online+ClamAV both deliver fast scanning!

## 🔄 Updating ArgusPi

To update to a newer version:

```bash
# Stop any running ArgusPi processes
sudo systemctl stop arguspi 2>/dev/null || true
pkill -f arguspi_scan_station.py 2>/dev/null || true

# Update code
git pull origin main

# Run setup again to apply new configurations
sudo python3 arguspi_setup.py

# Reboot to ensure clean startup
sudo reboot
```

## ❓ Need Help?

If you encounter issues during installation, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed troubleshooting steps.

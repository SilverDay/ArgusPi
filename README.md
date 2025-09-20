# ArgusPi USB Security Scanner

<div align="center">
  <h3>🛡️ Automated USB Malware Detection for Raspberry Pi 🛡️</h3>
  <p><em>Transform your Raspberry Pi into a dedicated USB security scanning station</em></p>
</div>

---

## 🎯 What is ArgusPi?

ArgusPi is a comprehensive USB security scanning solution that automatically detects, analyzes, and reports on potential malware threats in USB storage devices. Built specifically for Raspberry Pi, ArgusPi provides enterprise-grade USB security scanning with a user-friendly interface.

### ✨ Key Features

- **🔍 Automatic USB Detection** - Instantly detects when USB devices are inserted
- **🔒 Hardware Read-Only Protection** - Sets USB devices to read-only mode during scanning
- **🧬 Advanced File Analysis** - Computes SHA-256 hashes for all files
- **🦠 Multi-Layer Threat Detection** - Optional ClamAV local scanning + VirusTotal cloud analysis
- **🚦 Visual Status Indicators** - RGB LED status lights and touchscreen GUI
- **📊 Comprehensive Logging** - Detailed scan results and threat analysis
- **⚡ Real-Time Scanning** - No manual intervention required
- **🔐 Secure Mounting** - Uses `ro,noexec,nosuid,nodev` mount options

## 🖥️ User Interface

ArgusPi features a professional touchscreen interface optimized for Raspberry Pi displays:

- **Large ArgusPi branding** for clear identification
- **Color-coded status panels** (Blue: Waiting, Yellow: Scanning, Green: Clean, Red: Threats)
- **Real-time log display** showing scan progress and results
- **Touch-friendly design** optimized for 7-inch displays

## 🛠️ System Requirements

### Hardware
- **Raspberry Pi 3B+ or newer** (4GB+ RAM recommended)
- **MicroSD card** (16GB+ Class 10 recommended)
- **Optional: 7-inch touchscreen** for GUI display
- **Optional: RGB LED** for status indication

### Software
- **Raspberry Pi OS** (Bookworm or newer)
- **Python 3.9+** with pip
- **Root access** for installation
- **Internet connection** for VirusTotal API access

## 🚀 Quick Start

### 1. Download ArgusPi
```bash
git clone https://github.com/yourusername/arguspi.git
cd arguspi
```

### 2. Get VirusTotal API Key
1. Visit [VirusTotal](https://www.virustotal.com/)
2. Create a free account
3. Go to your profile and copy your API key

### 3. Run Setup
```bash
sudo python3 arguspi_setup.py
```

The setup script will:
- ✅ Validate your VirusTotal API key
- ✅ Configure system paths and settings
- ✅ Install required packages
- ✅ Create systemd service
- ✅ Set up USB auto-detection rules

### 4. Test Your Installation
1. Insert a USB device
2. Watch the LED status indicator or GUI
3. Check logs: `sudo journalctl -u arguspi -f`

## 📋 Configuration Options

During setup, you can configure:

| Option | Description | Default |
|--------|-------------|---------|
| **API Key** | VirusTotal API key for cloud scanning | *Required* |
| **Mount Path** | Directory for mounting USB devices | `/mnt/arguspi` |
| **Request Interval** | Seconds between VirusTotal requests | `20` (free tier) |
| **ClamAV Integration** | Enable local antivirus scanning | `No` |
| **RGB LED** | GPIO pins for status LED | `17,27,22` |
| **GUI Interface** | Enable touchscreen interface | `Yes` |

### Manual Configuration

Edit `/etc/arguspi/config.json`:
```json
{
  "api_key": "your_virustotal_api_key_here",
  "mount_base": "/mnt/arguspi",
  "request_interval": 20,
  "use_clamav": false,
  "use_led": true,
  "led_pins": {"red": 17, "green": 27, "blue": 22},
  "use_gui": true
}
```

## 🔧 Service Management

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

## 📊 Understanding Scan Results

### Status Indicators

| Status | LED Color | GUI Color | Description |
|--------|-----------|-----------|-------------|
| **Waiting** | Blue | Blue | Ready for USB insertion |
| **Scanning** | Yellow | Yellow | Analyzing files |
| **Clean** | Green | Green | No threats detected |
| **Infected** | Red (solid) | Red | Malware found |
| **Error** | Red (blinking) | Red | Scan error occurred |

### Log Format
```
2025-09-20 14:30:15 [ArgusPi-INFO] - ArgusPi detected USB device /dev/sdb1
2025-09-20 14:30:16 [ArgusPi-INFO] - Mounted /dev/sdb1 at /mnt/arguspi/sdb1
2025-09-20 14:30:20 [ArgusPi-INFO] - CLEAN | a1b2c3d4... | document.pdf | details: {...}
```

## 🔒 Security Features

ArgusPi implements multiple security layers:

1. **Hardware Read-Only** - USB devices are locked using `hdparm -r1`
2. **Secure Mounting** - Filesystems mounted with restrictive options
3. **Process Isolation** - Runs with minimal required privileges  
4. **Thread Safety** - Proper synchronization for concurrent operations
5. **Resource Cleanup** - Automatic unmounting on shutdown
6. **Input Validation** - All configuration values are validated

## 🐛 Troubleshooting

### Common Issues

**ArgusPi service won't start**
```bash
# Check service status
sudo systemctl status arguspi

# Check configuration
sudo python3 -c "import json; print(json.load(open('/etc/arguspi/config.json')))"
```

**USB devices not detected**
```bash
# Check udev rules
ls -la /etc/udev/rules.d/90-arguspi-readonly.rules

# Reload udev rules
sudo udevadm control --reload
```

**VirusTotal API errors**
```bash
# Test API key manually
curl -H "x-apikey: YOUR_API_KEY" https://www.virustotal.com/api/v3/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**GUI not displaying**
```bash
# Check X11 display
echo $DISPLAY

# Test Tkinter
python3 -c "import tkinter; print('Tkinter works')"
```

### Log Locations
- **Service logs**: `sudo journalctl -u arguspi`
- **Scan results**: `/var/log/arguspi.log`
- **System logs**: `/var/log/syslog`

## 🔄 Updating ArgusPi

To update to a newer version:

```bash
# Stop the service
sudo systemctl stop arguspi

# Update code
git pull origin main

# Run setup again
sudo python3 arguspi_setup.py

# Service will restart automatically
```

## 🚀 Future Enhancements

ArgusPi is actively developed with exciting features planned:

### 🎯 **Roadmap**
- **📋 USB Device Whitelisting** - Skip scanning for trusted devices
  - Configure by vendor ID, product ID, serial number, or device label  
  - Useful for personal devices, company-issued storage, or backup drives
  - Maintains security while improving workflow efficiency
- **📱 Mobile Integration** - Smartphone app for remote monitoring and notifications
- **🔌 Hardware Extensions** - Support for additional LED configurations and display types
- **📊 Advanced Analytics** - Detailed scan statistics, threat trends, and reporting dashboards
- **🌐 Network Integration** - Central management for multiple ArgusPi stations
- **🔒 Enhanced Security** - Support for additional antivirus engines and threat intelligence feeds

### 💡 **Want to contribute?** 
See our [Contributing Guidelines](CONTRIBUTING.md) to help bring these features to life!

## 🧪 Development & Testing

### Development Setup
```bash
# Clone repository
git clone https://github.com/yourusername/arguspi.git
cd arguspi

# Install development dependencies
pip3 install -r requirements-dev.txt

# Run in development mode
sudo python3 arguspi_scan_station.py
```

### Testing
```bash
# Test with a clean USB device
# Check logs for expected behavior

# Test with EICAR test file
# Should detect as malware
```

## 📈 Performance Considerations

- **Free VirusTotal Tier**: 4 requests/minute (500/day)
- **Memory Usage**: ~50MB base + file caching
- **Storage**: Minimal, only configuration and logs
- **CPU Impact**: Low, I/O bound operations

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Areas for Contribution
- 📱 Mobile app integration
- 🔌 Additional hardware support  
- 🧪 Enhanced testing frameworks
- 📚 Documentation improvements
- 🌐 Internationalization

## 📄 License

ArgusPi is released under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **VirusTotal** for their excellent API
- **Raspberry Pi Foundation** for amazing hardware
- **Python community** for fantastic libraries
- **Security researchers** who make tools like this necessary

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/arguspi/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/arguspi/discussions)
- **Security Issues**: Please report privately to security@yourproject.com

---

<div align="center">
  <p><strong>🛡️ Stay secure with ArgusPi! 🛡️</strong></p>
  <p><em>Made with ❤️ for the cybersecurity community</em></p>
</div>
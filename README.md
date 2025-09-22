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
- **🦠 Multi-Layer Threat Detection** - ClamAV local scanning + VirusTotal cloud analysis
- **🌐 Online & Offline Modes** - Works with or without internet connectivity _(perfect for air-gapped environments)_
- **⚡ Smart Scanning Strategy** - ClamAV pre-filters files to minimize VirusTotal API calls
- **🔗 SIEM Integration** - Send scan events and results to security monitoring platforms
- **🚦 Visual Status Indicators** - RGB LED status lights and touchscreen GUI
- **📊 Comprehensive Logging** - Detailed scan results and threat analysis

> **💡 Deployment Flexibility**: ArgusPi works in any environment - from internet-connected labs to secure air-gapped facilities!

## 🖥️ User Interface

ArgusPi features a professional touchscreen interface optimized for Raspberry Pi displays:

- **Large ArgusPi branding** for clear identification
- **Color-coded status panels** (Blue: Waiting, Yellow: Scanning, Green: Clean, Red: Threats)
- **Real-time log display** showing scan progress and results
- **Touch-friendly design** optimized for 7-inch displays

## � Quick Start

### Prerequisites

- Raspberry Pi 5 (4GB+ RAM recommended)
- Raspberry Pi OS (Bookworm or newer)
- Optional: 7-inch touchscreen, RGB LED, VirusTotal API key

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/silverday/arguspi.git
cd arguspi

# 2. Run the comprehensive setup script
sudo python3 arguspi_setup.py

# 3. Reboot to start ArgusPi
sudo reboot
```

That's it! The setup script now includes:

- ✅ System package updates and installation
- ✅ Python dependencies and X11 utilities
- ✅ ClamAV installation and database updates
- ✅ GUI diagnostic tool deployment
- ✅ Proper systemd service configuration with timing fixes
- ✅ Display configuration support
- ✅ Automatic diagnostic validation

ArgusPi will start automatically after reboot. Insert a USB device to test scanning.

### Performance Note

**Enable ClamAV during setup for best performance!** Without ClamAV, scanning 1000 files takes ~5.5 hours. With ClamAV, it takes ~10 minutes.

## 📚 Documentation

- **[📋 Detailed Installation Guide](INSTALLATION.md)** - Complete setup instructions and configuration options
- **[ Features & Configuration](FEATURES.md)** - All features, SIEM integration, and advanced settings
- **[🐛 Troubleshooting Guide](TROUBLESHOOTING.md)** - Solutions for common issues and problems
- **[🤝 Contributing Guidelines](CONTRIBUTING.md)** - How to contribute to the project

## 🔧 Troubleshooting

### GUI Not Starting After Reboot

If the GUI doesn't start after reboot, this is usually due to systemd service timing issues:

1. **Run diagnostics**:

   ```bash
   python3 /usr/local/bin/gui_diagnostic.py
   ```

2. **Check service status**:

   ```bash
   sudo systemctl status arguspi.service
   sudo journalctl -u arguspi.service -f
   ```

3. **Fix service configuration** (if diagnostic shows environment variable issues):
   ```bash
   bash fix_gui_service.sh
   sudo systemctl restart arguspi.service
   ```

### Common Issues

#### Display Configuration

- **Issue**: Screen appears upside down
- **Solution**: Config file moved to `/boot/firmware/config.txt` on newer Pi OS
  ```bash
  echo "display_rotate=2" | sudo tee -a /boot/firmware/config.txt
  sudo reboot
  ```

#### Service Environment Issues

- **Issue**: "No display name and no $DISPLAY environment variable"
- **Cause**: Service starting before desktop session
- **Solution**: The `fix_gui_service.sh` script adds proper timing dependencies

#### X11 Permission Errors

- **Issue**: "X11 server not accessible"
- **Cause**: Root service can't access user's X11 session
- **Solution**: Fix script configures xhost permissions automatically

### Files Overview

- `arguspi_scan_station.py` - Main application with enhanced diagnostics
- `arguspi_setup.py` - **Complete installation script** with all system preparation, fixes, and diagnostics
- `gui_diagnostic.py` - Comprehensive diagnostic tool for GUI issues (deployed automatically)
- `fix_gui_service.sh` - Service repair script for GUI timing issues (manual use if needed)

### Single Command Installation

The setup script now handles everything:

```bash
sudo python3 arguspi_setup.py
```

This **single command** includes:

- System package updates (`apt update && apt upgrade`)
- All required package installation (Python, X11, ClamAV, etc.)
- ClamAV database updates
- GUI diagnostic tool deployment
- Proper systemd service with timing fixes
- Display configuration
- Comprehensive validation and testing

## 📊 Scanning Modes

| Mode                 | Speed         | Requirements      | Use Case                       |
| -------------------- | ------------- | ----------------- | ------------------------------ |
| **Offline (ClamAV)** | ~10 minutes\* | None              | Air-gapped/secure environments |
| **Online + ClamAV**  | ~10 minutes\* | Internet, API key | Best performance + detection   |
| **Cloud-only**       | ~5.5 hours\*  | Internet, API key | Maximum cloud analysis         |

_\*For 1000 files. Actual times vary based on file sizes and types._

## 🔧 Service Management

```bash
# Check status
sudo systemctl status arguspi

# View logs
sudo journalctl -u arguspi -f

# Restart service
sudo systemctl restart arguspi
```

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

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/silverday/arguspi/issues)
- **Discussions**: [GitHub Discussions](https://github.com/silverday/arguspi/discussions)
- **Security Issues**: Please report privately to security@yourproject.com

---

<div align="center">
  <p><strong>🛡️ Stay secure with ArgusPi! 🛡️</strong></p>
  <p><em>Made with ❤️ for the cybersecurity community</em></p>
</div>

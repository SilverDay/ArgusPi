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

# 2. Run the setup script
sudo python3 arguspi_setup.py

# 3. Enable desktop autologin (for GUI)
sudo raspi-config
# Navigate to: System Options → Boot / Auto Login → Desktop Autologin

# 4. Reboot
sudo reboot
```

That's it! Insert a USB device to test scanning.

### Performance Note

**Enable ClamAV during setup for best performance!** Without ClamAV, scanning 1000 files takes ~5.5 hours. With ClamAV, it takes ~10 minutes.

## 📚 Documentation

- **[📋 Detailed Installation Guide](INSTALLATION.md)** - Complete setup instructions and configuration options
- **[ Features & Configuration](FEATURES.md)** - All features, SIEM integration, and advanced settings
- **[🐛 Troubleshooting Guide](TROUBLESHOOTING.md)** - Solutions for common issues and problems
- **[🤝 Contributing Guidelines](CONTRIBUTING.md)** - How to contribute to the project

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

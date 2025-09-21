# Contributing to ArgusPi

Thank you for your interest in ## 🎯 Areas for Contribution

### High Priority

- **📋 USB Device Whitelisting** - Allow trusted devices to bypass scanning
  - Whitelist by vendor ID, product ID, serial number, or device label
  - Configuration interface for managing whitelist entries
  - Automatic learning mode for frequently used devices
- **📱 Mobile Integration** - Smartphone app for remote monitoring
- **🔌 Hardware Support** - Support for additional LED configurations
- **🧪 Testing Framework** - Automated testing suite
- **📊 Analytics** - Better scan statistics and reportinguting to ArgusPi! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or request features
- Include detailed information about your environment
- Provide steps to reproduce any issues
- Include relevant log files or error messages

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly on a Raspberry Pi
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 🧪 Development Environment

### Requirements

- Raspberry Pi 5 (for hardware testing)
- Python 3.9+
- Git

### Setup

```bash
git clone https://github.com/silverday/arguspi.git
cd arguspi

# Run the setup script (handles modern Python environments automatically)
sudo python3 arguspi_setup.py
```

### Troubleshooting Installation

**"externally-managed-environment" error:**
If you encounter this error, the setup script will automatically handle it by:

1. First trying to install packages via `apt` (preferred)
2. Falling back to `pip` with `--break-system-packages` if needed
3. Providing manual installation instructions if all methods fail

**Manual installation if needed:**

```bash
# Install Python packages via apt (recommended)
sudo apt install python3-pyudev python3-requests python3-gpiozero python3-tk

# Or use pip with break-system-packages flag
sudo pip3 install --break-system-packages pyudev requests
```

## 📋 Coding Standards

### Python Style

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write docstrings for all public functions
- Keep functions focused and concise

### Code Organization

- Maintain separation between GUI, scanning logic, and system integration
- Use proper exception handling
- Implement logging for debugging
- Write thread-safe code

### Testing

- Test on actual Raspberry Pi hardware when possible
- Test with various USB device types
- Verify security features (read-only mounting, etc.)
- Test error conditions and edge cases

## 🎯 Areas for Contribution

### High Priority

- 📱 **Mobile Integration** - Smartphone app for remote monitoring
- 🔌 **Hardware Support** - Support for additional LED configurations
- 🧪 **Testing Framework** - Automated testing suite
- 📊 **Analytics** - Better scan statistics and reporting

### Medium Priority

- 🌐 **Internationalization** - Multi-language support
- 🎨 **UI Improvements** - Enhanced GUI designs
- 📚 **Documentation** - More detailed guides and tutorials
- 🔧 **Configuration** - Web-based configuration interface

### Low Priority

- 🎵 **Audio Notifications** - Sound alerts for scan results
- 📧 **Email Alerts** - Notification system integration
- 🌈 **Themes** - Customizable GUI color schemes
- 📈 **Metrics** - Performance monitoring dashboard

## 🔒 Security Considerations

When contributing to ArgusPi, please keep security in mind:

- Never log sensitive information (API keys, file contents)
- Validate all user inputs
- Follow secure coding practices
- Test security features thoroughly
- Report security issues privately

## 📝 Documentation

### Code Documentation

- Use clear, descriptive variable and function names
- Write comprehensive docstrings
- Include type hints
- Comment complex logic

### User Documentation

- Update README.md for new features
- Add troubleshooting information
- Include configuration examples
- Provide clear installation instructions

## 🧾 Commit Messages

Use clear, descriptive commit messages:

```
feat: add email notification support
fix: resolve USB detection race condition
docs: update installation instructions
refactor: improve LED status handling
test: add unit tests for file hashing
```

## 🏷️ Versioning

ArgusPi follows Semantic Versioning (SemVer):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

## 📄 License

By contributing to ArgusPi, you agree that your contributions will be licensed under the MIT License.

## ❓ Questions?

- Create a GitHub Discussion for general questions
- Use GitHub Issues for bug reports and feature requests
- Email security concerns privately to security@yourproject.com

Thank you for helping make ArgusPi better! 🛡️

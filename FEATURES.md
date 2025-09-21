# ArgusPi Features & Configuration

This document provides detailed information about ArgusPi's features, capabilities, and advanced configuration options.

## 🎯 Core Features

### 🔍 Automatic USB Detection

- Instantly detects when USB devices are inserted
- Supports multiple filesystem types (FAT32, NTFS, ext4)
- Automatic device mounting with secure options

### 🔒 Hardware Security

- **Hardware Read-Only Protection**: Sets USB devices to read-only mode using `hdparm -r1`
- **Secure Mounting**: Uses `ro,noexec,nosuid,nodev` mount options
- **Process Isolation**: Runs with minimal required privileges

### 🧬 Advanced File Analysis

- **SHA-256 Hashing**: Computes cryptographic hashes for all files
- **File Type Detection**: Identifies file types regardless of extension
- **Metadata Extraction**: Gathers file attributes and timestamps

### 🦠 Multi-Layer Threat Detection

#### Local ClamAV Scanning

- **Fast Pre-filtering**: Scans files locally before cloud analysis
- **Offline Capability**: Works without internet connection
- **Regular Updates**: Virus definitions updated automatically
- **Performance Boost**: Reduces VirusTotal API calls by 90%+

#### VirusTotal Cloud Analysis

- **70+ Antivirus Engines**: Comprehensive threat detection
- **Behavioral Analysis**: Advanced malware detection techniques
- **Threat Intelligence**: Real-time global threat data
- **False Positive Reduction**: Multiple engine consensus

### 🌐 Deployment Modes

#### Online Mode (Recommended)

- **ClamAV + VirusTotal**: Best of both worlds
- **Smart Filtering**: Only suspicious files sent to cloud
- **Performance**: Fast local scanning with cloud backup

#### Offline Mode (Air-Gapped)

- **ClamAV Only**: Complete offline operation
- **Security**: No network connectivity required
- **Compliance**: Perfect for classified environments

#### Cloud-Only Mode

- **VirusTotal Only**: Every file analyzed in cloud
- **Comprehensive**: Maximum threat detection
- **Slower**: Limited by API rate limits

## 🖥️ User Interface

### Touchscreen GUI

- **Professional Design**: Clean, intuitive interface
- **Real-time Status**: Live scanning progress
- **Color-coded Results**: Instant visual feedback
- **Touch Optimized**: Perfect for 7-inch displays
- **ArgusPi Branding**: Clear station identification

### RGB LED Indicators

| Status       | LED Color | Behavior | Description             |
| ------------ | --------- | -------- | ----------------------- |
| **Waiting**  | Blue      | Solid    | Ready for USB insertion |
| **Scanning** | Yellow    | Pulsing  | Analyzing files         |
| **Clean**    | Green     | Solid    | No threats detected     |
| **Infected** | Red       | Solid    | Malware found           |
| **Error**    | Red       | Blinking | Scan error occurred     |

## 🔗 SIEM Integration

### Supported Platforms

- **Splunk** - Via syslog or HTTP Event Collector
- **Elastic Stack (ELK)** - Via Logstash syslog input
- **IBM QRadar** - Via syslog or REST API
- **Microsoft Sentinel** - Via Log Analytics API
- **Any RFC 5424 SIEM** - Via standard syslog
- **Custom Systems** - Via HTTP webhooks

### Event Types

| Event Type        | Description                | Severity | Triggers                    |
| ----------------- | -------------------------- | -------- | --------------------------- |
| `scan_started`    | USB device scan begins     | Low      | USB insertion               |
| `scan_completed`  | Scan finished with results | Low/High | Scan completion             |
| `threat_detected` | Malware found on device    | High     | ClamAV/VirusTotal detection |
| `scan_error`      | Scan failed or interrupted | Medium   | Device removal, errors      |

### Sample SIEM Event

```json
{
  "timestamp": "2025-09-20T14:30:00Z",
  "source": "arguspi",
  "station_name": "reception-desk",
  "hostname": "raspberrypi",
  "event_type": "threat_detected",
  "severity": "high",
  "data": {
    "file_path": "/mnt/arguspi/sdb1/suspicious.exe",
    "file_name": "suspicious.exe",
    "file_hash": "a1b2c3d4e5f6...",
    "device": "sdb1",
    "detection_method": "virustotal",
    "malicious_count": 45,
    "suspicious_count": 12,
    "total_engines": 70,
    "first_submission": "2025-09-20T14:25:00Z",
    "last_analysis": "2025-09-20T14:29:30Z"
  }
}
```

### Configuration Examples

**Splunk Integration:**

```json
{
  "siem_enabled": true,
  "siem_type": "syslog",
  "siem_server": "splunk-indexer.company.com",
  "siem_port": 514,
  "siem_facility": "local0"
}
```

**Custom Webhook:**

```json
{
  "siem_enabled": true,
  "siem_type": "webhook",
  "siem_webhook_url": "https://your-siem.com/api/events",
  "siem_headers": {
    "Authorization": "Bearer your-token",
    "Content-Type": "application/json"
  }
}
```

## ⚡ Performance & Scanning Behavior

### Scanning Strategies

#### Smart Scanning (ClamAV + VirusTotal)

1. **Pre-scan**: ClamAV analyzes all files locally
2. **Filter**: Only suspicious/infected files sent to VirusTotal
3. **Verify**: Cloud analysis confirms threats
4. **Report**: Consolidated results from both engines

#### Performance Metrics

| USB Contents     | Offline Mode    | Online (no ClamAV) | Online + ClamAV |
| ---------------- | --------------- | ------------------ | --------------- |
| 100 clean files  | **~2 minutes**  | ~33 minutes        | **~2 minutes**  |
| 500 clean files  | **~5 minutes**  | ~2.8 hours         | **~5 minutes**  |
| 1000 clean files | **~10 minutes** | ~5.5 hours         | **~10 minutes** |
| Mixed content    | **~3-12 min**   | ~45min-6hrs        | **~3-15 min**   |

### Resource Usage

- **Memory**: ~50MB base + ~5MB per GB scanned
- **CPU**: Low usage, I/O bound operations
- **Storage**: Minimal, only logs and configuration
- **Network**: VirusTotal API calls only when needed

## 🛡️ Security Features

### Defense in Depth

1. **Hardware Level**: USB devices locked read-only
2. **Filesystem Level**: Restrictive mount options
3. **Process Level**: Minimal privileges, sandboxed execution
4. **Network Level**: Encrypted API communications
5. **Data Level**: File hashing and integrity checks

### Secure Architecture

- **Input Validation**: All user inputs sanitized
- **Thread Safety**: Proper synchronization for concurrent operations
- **Resource Cleanup**: Automatic cleanup on shutdown/errors
- **Error Handling**: Graceful failure modes
- **Logging**: Comprehensive audit trail

## 📊 Station Management

### Multi-Station Deployments

- **Unique Identifiers**: Each station has distinct name
- **Centralized Logging**: SIEM integration for monitoring
- **Consistent Configuration**: Standardized setup process
- **Remote Monitoring**: Status via SIEM dashboards

### Naming Conventions

Use descriptive station names for easy identification:

- `reception-desk` - Main entrance security
- `lab-entrance` - Laboratory access point
- `security-checkpoint-1` - Primary security station
- `visitor-kiosk` - Guest USB scanning
- `executive-floor` - Executive area protection

## 🔧 Advanced Configuration

### Environment Variables

```bash
# Override default configuration path
export ARGUSPI_CONFIG="/custom/path/config.json"

# Set custom log level
export ARGUSPI_LOG_LEVEL="DEBUG"

# Custom mount base
export ARGUSPI_MOUNT_BASE="/custom/mount/path"
```

### Service Customization

Edit `/etc/systemd/system/arguspi.service` for custom settings:

```ini
[Unit]
Description=ArgusPi USB Security Scanner
After=network.target

[Service]
Type=simple
User=arguspi
Group=arguspi
ExecStart=/usr/bin/python3 /usr/local/bin/arguspi_scan_station.py
Restart=always
RestartSec=5
Environment=ARGUSPI_CONFIG=/etc/arguspi/config.json

[Install]
WantedBy=multi-user.target
```

### Performance Tuning

```json
{
  "performance": {
    "max_concurrent_scans": 2,
    "file_size_limit": "100MB",
    "timeout_seconds": 300,
    "cache_results": true,
    "cache_duration_hours": 24
  }
}
```

## 🚀 Future Roadmap

### Planned Features

- **📋 USB Device Whitelisting**: Skip scanning for trusted devices
- **📱 Mobile Integration**: Smartphone app for monitoring
- **🔌 Hardware Extensions**: Additional LED and display support
- **📊 Advanced Analytics**: Detailed statistics and reporting
- **🌐 Network Integration**: Central management console
- **🔒 Enhanced Security**: Additional antivirus engines

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and how to contribute new features.

### Version History

- **v1.0.0**: Initial release with core scanning functionality
- **v1.1.0**: Added SIEM integration and improved GUI
- **v1.2.0**: Enhanced performance and ClamAV integration
- **v1.3.0**: Dynamic user detection and setup improvements

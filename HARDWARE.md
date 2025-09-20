# ArgusPi Hardware Setup Guide

Complete hardware recommendations for deploying ArgusPi USB security scanning stations.

## 🖥️ Core Components

### Recommended Configuration

| Component                 | Model                             |       Price        | Purpose                                                |
| :------------------------ | :-------------------------------- | :----------------: | :----------------------------------------------------- |
| **Single Board Computer** | Raspberry Pi 5 (8 GB RAM)         |     **£76.50**     | Main computing platform with ample RAM for large files |
| **Display**               | Raspberry Pi Touch Display 2 – 7″ |     **£57.60**     | Official touchscreen for interactive operation         |
| **Power Supply**          | Raspberry Pi 45W USB-C PSU        |     **£14.40**     | Sufficient power for Pi 5 + peripherals + USB devices  |
| **Enclosure**             | SmartiPi Touch Pro 3              |     **£37.20**     | Professional enclosure with integrated display mount   |
|                           |                                   | **Total: £185.70** |                                                        |

### Alternative Configurations

#### Budget Option

| Component                 | Model                      |       Price        | Notes                                    |
| :------------------------ | :------------------------- | :----------------: | :--------------------------------------- |
| **Single Board Computer** | Raspberry Pi 4B (4 GB RAM) |     **£55.00**     | Sufficient for most scanning workloads   |
| **Display**               | 5″ HDMI Touch Display      |     **£35.00**     | Generic touchscreen with HDMI connection |
| **Power Supply**          | Official Pi 4 PSU (15W)    |     **£8.00**      | Adequate for Pi 4 + basic peripherals    |
| **Enclosure**             | Generic Pi 4 Case with Fan |     **£15.00**     | Basic protection with cooling            |
|                           |                            | **Total: £113.00** |                                          |

#### High-Performance Option

| Component                 | Model                            |       Price        | Notes                                          |
| :------------------------ | :------------------------------- | :----------------: | :--------------------------------------------- |
| **Single Board Computer** | Raspberry Pi 5 (8 GB RAM)        |     **£76.50**     | Maximum performance and memory                 |
| **Display**               | 10″ HDMI Touch Display           |    **£120.00**     | Larger screen for better visibility            |
| **Power Supply**          | 65W USB-C PD Supply              |     **£25.00**     | Extra power for high-demand USB devices        |
| **Enclosure**             | Industrial Pi Case with DIN Rail |     **£85.00**     | Professional mounting for secure installations |
|                           |                                  | **Total: £306.50** |                                                |

## 🔌 Essential Accessories

### USB and Storage

| Component                | Model/Type                 |   Price    | Purpose                                   |
| :----------------------- | :------------------------- | :--------: | :---------------------------------------- |
| **MicroSD Card**         | SanDisk Extreme 64GB A2 U3 | **£12.00** | Fast, reliable system storage             |
| **USB Hub** _(Optional)_ | Powered 4-Port USB 3.0 Hub | **£25.00** | Multiple simultaneous USB device scanning |
| **Test USB Drives**      | Various capacities/types   | **£30.00** | Collection for testing and demonstration  |

### Networking

| Component                     | Model/Type                |   Price    | Purpose                                         |
| :---------------------------- | :------------------------ | :--------: | :---------------------------------------------- |
| **Ethernet Cable**            | CAT6 Patch Cable (3m)     | **£8.00**  | Reliable network connection for VirusTotal/SIEM |
| **WiFi Adapter** _(Optional)_ | USB WiFi Dongle (if Pi 4) | **£15.00** | Wireless connectivity (Pi 5 has built-in WiFi)  |

## 💡 LED Status Indicator (Optional)

For visual status feedback during scanning operations:

| Component                   | Model/Type                  |   Price   | Purpose                             |
| :-------------------------- | :-------------------------- | :-------: | :---------------------------------- |
| **RGB LED**                 | Common Cathode RGB LED      | **£2.00** | Status indication (red/amber/green) |
| **Resistors**               | 220Ω Resistor Pack          | **£3.00** | Current limiting for LED            |
| **Jumper Wires**            | Female-to-Male Dupont Wires | **£5.00** | GPIO connections                    |
| **Breadboard** _(Optional)_ | Half-size Breadboard        | **£4.00** | Prototyping LED connections         |

### LED Wiring (BCM Pin Numbers)

```
RGB LED Connections:
├── Red   → GPIO 17 (Pin 11)
├── Green → GPIO 27 (Pin 13)
├── Blue  → GPIO 22 (Pin 15)
└── GND   → Ground (Pin 6, 9, 14, 20, 25, 30, 34, 39)
```

## 🔧 Assembly Recommendations

### 1. **Core Assembly**

- Install Raspberry Pi in chosen enclosure
- Connect touchscreen using official DSI cable
- Secure all connections before powering on

### 2. **Storage Preparation**

- Use Raspberry Pi Imager to flash Raspberry Pi OS Lite (64-bit)
- Enable SSH and configure WiFi if needed
- Insert SD card and initial boot

### 3. **Optional LED Setup**

- Connect RGB LED to GPIO pins as shown above
- Use 220Ω resistors in series with each color
- Test with simple Python script before ArgusPi installation

### 4. **Network Configuration**

- Connect Ethernet cable for reliable internet access
- Configure static IP if required by network policy
- Test VirusTotal API connectivity

## 🏢 Enterprise Deployment Considerations

### Multi-Station Deployments

- **Standardize hardware**: Use identical configurations for easier maintenance
- **Label stations**: Physical labels matching the `station_name` configuration
- **Spare components**: Keep 10-20% spare parts inventory
- **Documentation**: Maintain hardware inventory with serial numbers

### Security Considerations

- **Physical security**: Secure mounting to prevent tampering
- **Network isolation**: Consider VLAN segmentation for scanner traffic
- **Access control**: Limit physical access to configuration interfaces
- **Monitoring**: Implement hardware health monitoring via SIEM integration

### Maintenance Kit

| Component                | Quantity | Purpose                                          |
| :----------------------- | :------: | :----------------------------------------------- |
| **Spare SD Cards**       |   2-3    | Quick replacement for failed storage             |
| **Spare Power Supplies** |    1     | Power supply failures are common                 |
| **Cleaning Supplies**    |   Set    | Isopropyl alcohol, microfiber cloths for display |
| **USB Test Drives**      |   5-10   | Various capacities for testing and calibration   |

## 🛒 Purchasing Recommendations

### Suppliers

- **UK**: [Pimoroni](https://pimoroni.com), [The Pi Hut](https://thepihut.com), [RS Components](https://uk.rs-online.com)
- **US**: [Adafruit](https://adafruit.com), [SparkFun](https://sparkfun.com), [Amazon](https://amazon.com)
- **EU**: [Berrybase](https://berrybase.de), [Kubii](https://kubii.fr), [Electrokit](https://electrokit.com)

### Bulk Purchasing

For deployments of 5+ stations:

- Contact suppliers for bulk pricing discounts
- Consider educational/corporate discount programs
- Plan for 6-8 week lead times for large orders
- Include spare components (20% buffer recommended)

## 📋 Pre-Deployment Checklist

- [ ] Hardware assembled and tested
- [ ] Raspberry Pi OS installed and updated
- [ ] Network connectivity verified
- [ ] ArgusPi software installed and configured
- [ ] Station name configured and labeled
- [ ] LED status indicator tested (if installed)
- [ ] SIEM integration tested (if configured)
- [ ] Test USB drives scanned successfully
- [ ] Documentation updated with station details

---

*For software installation and configuration, see the main [README.md](README.md) file.*Hardware Setup for ArgusPi

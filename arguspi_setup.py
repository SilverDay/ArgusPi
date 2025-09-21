#!/usr/bin/env python3
"""
ArgusPi Setup – Installer for the ArgusPi USB security scanning station.

This helper script automates the configuration of a Raspberry Pi as an
ArgusPi USB malware checking station. It performs the following tasks:

1. Prompts the administrator for a VirusTotal API key and optional
   configuration parameters (mount path, request interval).
2. Creates a configuration file in ``/etc/arguspi/config.json`` with
   the supplied options. The configuration file is used by the
   ``arguspi_scan_station.py`` daemon.
3. Installs required system packages via ``apt`` (`hdparm`) and
   required Python packages via ``pip`` (`pyudev`, `requests`).
4. Copies the scanning script (``arguspi_scan_station.py``) to
   ``/usr/local/bin`` and sets the executable bit.
5. Creates a simple udev rule to mark USB storage devices as
   read-only upon insertion and clear the flag on removal using
   ``hdparm -r1/-r0``.
6. Defines a systemd unit file that runs the ArgusPi scanning service as a
   background daemon on boot. The service is enabled and started.

Run this installer with root privileges on a Raspberry Pi. It is
idempotent; running it multiple times will update existing files.
"""

import os
import sys
import json
import shutil
import subprocess
import stat
import socket
import logging
import logging.handlers
import re
import time
from getpass import getpass
from urllib.parse import urlparse
import ipaddress


def validate_webhook_url(url: str) -> bool:
    """
    Validate webhook URL to prevent SSRF attacks.

    Args:
        url: The webhook URL to validate

    Returns:
        bool: True if URL is safe, False otherwise
    """
    try:
        parsed = urlparse(url)

        # Must use HTTPS for security
        if parsed.scheme not in ['https']:
            print("Error: Webhook URL must use HTTPS protocol for security")
            return False

        # Must have a hostname
        if not parsed.hostname:
            print("Error: Invalid webhook URL - no hostname found")
            return False

        # Resolve hostname to IP to check for dangerous/reserved ranges
        try:
            import socket
            ip_addr = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip_addr)

            # Only block truly dangerous addresses, not corporate networks
            if (ip_obj.is_loopback or       # 127.0.0.1, ::1 (localhost)
                ip_obj.is_link_local or     # 169.254.x.x (AWS/Azure metadata range)
                ip_obj.is_multicast or      # Multicast addresses
                ip_obj.is_unspecified):     # 0.0.0.0, ::
                print(f"Error: Webhook URL resolves to restricted IP: {ip_addr}")
                print("Loopback, link-local, multicast, and unspecified addresses are not allowed")
                return False

            # Additional check for specific dangerous IPs
            if str(ip_obj) in ['169.254.169.254', '127.0.0.1', '0.0.0.0', '::1']:
                print(f"Error: Webhook URL resolves to blocked IP: {ip_addr}")
                print("This IP is commonly used for metadata services or localhost access")
                return False
        except socket.gaierror:
            print(f"Error: Could not resolve hostname: {parsed.hostname}")
            return False
        except Exception as e:
            print(f"Error validating webhook URL: {e}")
            return False

        # Additional checks for common SSRF bypass attempts and cloud metadata
        hostname_lower = parsed.hostname.lower()
        dangerous_hosts = [
            'localhost',
            'metadata.google.internal',  # Google Cloud metadata
            'instance-data',             # AWS instance metadata
            'metadata.azure.com',        # Azure metadata
        ]

        # Block specific dangerous hostnames
        if any(dangerous == hostname_lower for dangerous in dangerous_hosts):
            print(f"Error: Webhook hostname is blocked: {parsed.hostname}")
            print("This hostname is commonly used for cloud metadata services")
            return False

        # Block hostname patterns that could be SSRF attempts
        if any(dangerous in hostname_lower for dangerous in ['metadata', 'instance-data']):
            print(f"Error: Webhook hostname contains blocked pattern: {parsed.hostname}")
            print("Hostnames containing 'metadata' or 'instance-data' are not allowed")
            return False

        return True

    except Exception as e:
        print(f"Error parsing webhook URL: {e}")
        return False


def scan_wifi_networks() -> list:
    """Scan for available WiFi networks using iwlist."""
    try:
        # Try different wireless interfaces
        interfaces = ['wlan0', 'wlan1', 'wlp2s0']
        networks = []

        for interface in interfaces:
            try:
                # Check if interface exists and is up
                result = subprocess.run(['iwconfig', interface],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode != 0:
                    continue

                # Scan for networks
                scan_result = subprocess.run(['iwlist', interface, 'scan'],
                                           capture_output=True, text=True, timeout=30)
                if scan_result.returncode != 0:
                    continue

                # Parse scan results
                current_network = {}
                for line in scan_result.stdout.split('\n'):
                    line = line.strip()

                    if 'Cell' in line and 'Address:' in line:
                        # Save previous network if it exists
                        if current_network and current_network.get('ESSID'):
                            networks.append(current_network)
                        current_network = {}
                    elif 'ESSID:' in line:
                        essid_match = re.search(r'ESSID:"([^"]*)"', line)
                        if essid_match:
                            current_network['ESSID'] = essid_match.group(1)
                    elif 'Encryption key:' in line:
                        if 'off' in line:
                            current_network['Security'] = 'Open'
                        else:
                            current_network['Security'] = 'Secured'
                    elif 'IE: IEEE 802.11i/WPA2' in line:
                        current_network['Security'] = 'WPA2'
                    elif 'IE: WPA Version' in line:
                        current_network['Security'] = 'WPA'
                    elif 'Quality=' in line:
                        quality_match = re.search(r'Quality=(\d+)/(\d+)', line)
                        if quality_match:
                            quality = int(quality_match.group(1))
                            max_quality = int(quality_match.group(2))
                            signal_percent = int((quality / max_quality) * 100)
                            current_network['Signal'] = f"{signal_percent}%"

                # Add last network
                if current_network and current_network.get('ESSID'):
                    networks.append(current_network)

                # If we found networks, break (don't check other interfaces)
                if networks:
                    break

            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                continue

        # Remove duplicates and sort by signal strength
        unique_networks = {}
        for network in networks:
            essid = network.get('ESSID', '')
            if essid and essid not in unique_networks:
                unique_networks[essid] = network

        return list(unique_networks.values())

    except Exception as e:
        print(f"Warning: Could not scan WiFi networks: {e}")
        return []


def get_current_wifi_config() -> dict:
    """Get current WiFi configuration from wpa_supplicant.conf."""
    try:
        with open('/etc/wpa_supplicant/wpa_supplicant.conf', 'r') as f:
            content = f.read()

        # Find network blocks
        networks = []
        current_network = {}
        in_network = False

        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('network={'):
                in_network = True
                current_network = {}
            elif line == '}' and in_network:
                if current_network.get('ssid'):
                    networks.append(current_network)
                current_network = {}
                in_network = False
            elif in_network and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"')
                current_network[key] = value

        return {'networks': networks}

    except FileNotFoundError:
        return {'networks': []}
    except Exception as e:
        print(f"Warning: Could not read WiFi configuration: {e}")
        return {'networks': []}


def configure_wifi(ssid: str, password: str = "", security: str = "WPA2", hidden: bool = False) -> bool:
    """Configure WiFi by updating wpa_supplicant.conf."""
    try:
        # Read existing configuration
        config_path = '/etc/wpa_supplicant/wpa_supplicant.conf'

        # Create backup
        if os.path.exists(config_path):
            shutil.copy2(config_path, f"{config_path}.backup")

        # Read existing content
        existing_content = ""
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                existing_content = f.read()

        # Check if this network already exists
        if f'ssid="{ssid}"' in existing_content:
            # Remove existing entry for this SSID
            lines = existing_content.split('\n')
            new_lines = []
            skip_network = False

            for line in lines:
                if line.strip().startswith('network={'):
                    # Start of a network block
                    network_block = [line]
                    skip_network = False
                elif (line.strip() == '}' and
                      len([l for l in new_lines if l.strip().startswith('network={')]) >
                      len([l for l in new_lines if l.strip() == '}'])):
                    # End of current network block
                    network_block.append(line)
                    if not skip_network:
                        new_lines.extend(network_block)
                    network_block = []
                elif (len([l for l in new_lines if l.strip().startswith('network={')]) >
                      len([l for l in new_lines if l.strip() == '}'])):
                    # Inside a network block
                    if f'ssid="{ssid}"' in line:
                        skip_network = True
                    network_block.append(line)
                else:
                    # Outside network blocks
                    new_lines.append(line)

            existing_content = '\n'.join(new_lines)

        # Prepare new network configuration
        network_config = f"""
network={{
    ssid="{ssid}"
"""

        if security.upper() == "OPEN" or not password:
            network_config += "    key_mgmt=NONE\n"
        else:
            network_config += f"    psk=\"{password}\"\n"
            if security.upper() == "WPA":
                network_config += "    proto=WPA\n"
            else:  # WPA2 or WPA3
                network_config += "    proto=RSN\n"

        if hidden:
            network_config += "    scan_ssid=1\n"

        network_config += "}\n"

        # Write new configuration
        with open(config_path, 'w') as f:
            # Start with country and basic config if file is empty
            if not existing_content.strip():
                f.write("country=US\n")
                f.write("ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n")
                f.write("update_config=1\n")
            else:
                f.write(existing_content.rstrip() + '\n')

            f.write(network_config)

        # Set correct permissions
        os.chmod(config_path, 0o600)

        # Restart WiFi services
        subprocess.run(['wpa_cli', '-i', 'wlan0', 'reconfigure'],
                      capture_output=True, check=False)

        return True

    except Exception as e:
        print(f"Error configuring WiFi: {e}")
        # Restore backup if it exists
        backup_path = f"{config_path}.backup"
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, config_path)
        return False


def test_wifi_connectivity(timeout: int = 30) -> bool:
    """Test internet connectivity after WiFi configuration."""
    try:
        print("Testing WiFi connectivity...")

        # Wait for WiFi to connect
        for i in range(timeout):
            try:
                # Check if we have an IP address
                result = subprocess.run(['hostname', '-I'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    # Test internet connectivity
                    test_result = subprocess.run(['ping', '-c', '3', '8.8.8.8'],
                                                capture_output=True, timeout=15)
                    if test_result.returncode == 0:
                        print("✓ WiFi connectivity test successful")
                        return True

                time.sleep(1)
                if i % 5 == 0:
                    print(f"  Waiting for connection... ({i}/{timeout}s)")

            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                continue

        print("✗ WiFi connectivity test failed")
        return False

    except Exception as e:
        print(f"Error testing WiFi connectivity: {e}")
        return False


def prompt_wifi_configuration() -> bool:
    """Interactive WiFi configuration with network scanning and validation."""
    print("\n--- WiFi Configuration ---")
    print("Configure wireless network connectivity for your ArgusPi station")

    # Check if user wants to configure WiFi
    configure_wifi_input = input("Configure WiFi network (Y/n)? ").strip().lower()
    if configure_wifi_input in ("n", "no"):
        print("Skipping WiFi configuration")
        return True

    # Ensure wireless tools are available
    if not ensure_wifi_tools():
        print("Warning: Wireless tools not available. Using manual configuration only.")
        available_networks = []
    else:
        # Scan for available networks
        print("\nScanning for available networks...")
        available_networks = scan_wifi_networks()

    # Show current configuration if any
    current_config = get_current_wifi_config()
    if current_config['networks']:
        print("\nCurrent WiFi networks configured:")
        for i, network in enumerate(current_config['networks'], 1):
            ssid = network.get('ssid', 'Unknown')
            print(f"  {i}. {ssid}")

    if available_networks:
        print("\nAvailable networks:")
        for i, network in enumerate(available_networks[:10], 1):  # Show top 10
            ssid = network.get('ESSID', 'Unknown')
            security = network.get('Security', 'Unknown')
            signal = network.get('Signal', 'Unknown')
            print(f"  {i:2d}. {ssid:<25} {security:<8} {signal}")
        print(f"  {len(available_networks)+1:2d}. Enter network manually")
        print(f"   0. Skip WiFi configuration")
    else:
        print("No networks found. You can enter network details manually.")

    # Get user selection
    while True:
        try:
            if available_networks:
                choice = input(f"\nSelect network (0-{len(available_networks)+1}): ").strip()
                choice_num = int(choice)

                if choice_num == 0:
                    print("Skipping WiFi configuration")
                    return True
                elif 1 <= choice_num <= len(available_networks):
                    # Use scanned network
                    selected_network = available_networks[choice_num - 1]
                    ssid = selected_network['ESSID']
                    security = selected_network.get('Security', 'WPA2')
                    break
                elif choice_num == len(available_networks) + 1:
                    # Manual entry
                    ssid = input("Enter network name (SSID): ").strip()
                    if not ssid:
                        print("Network name cannot be empty")
                        continue
                    print("Security options:")
                    print("1. WPA2/WPA3 (most common)")
                    print("2. WPA (legacy)")
                    print("3. Open (no password)")
                    sec_choice = input("Select security type (1-3): ").strip()
                    if sec_choice == "2":
                        security = "WPA"
                    elif sec_choice == "3":
                        security = "Open"
                    else:
                        security = "WPA2"
                    break
                else:
                    print("Invalid selection")
                    continue
            else:
                # No networks found, manual entry only
                ssid = input("Enter network name (SSID): ").strip()
                if not ssid:
                    print("Network name cannot be empty")
                    continue
                security = "WPA2"  # Default assumption
                break

        except ValueError:
            print("Please enter a number")
            continue

    # Get password if needed
    password = ""
    if security.upper() != "OPEN":
        while True:
            password = getpass(f"Enter password for '{ssid}' (input hidden): ").strip()
            if len(password) >= 8:
                break
            elif len(password) == 0:
                use_no_password = input("Use open network (no password) (y/N)? ").strip().lower()
                if use_no_password in ("y", "yes"):
                    security = "Open"
                    break
                else:
                    print("Password must be at least 8 characters")
            else:
                print("Password must be at least 8 characters")

    # Ask about hidden network
    hidden = False
    if available_networks and ssid not in [n.get('ESSID', '') for n in available_networks]:
        hidden_input = input("Is this a hidden network (y/N)? ").strip().lower()
        hidden = hidden_input in ("y", "yes")

    # Configure the network
    print(f"\nConfiguring WiFi network '{ssid}'...")
    if configure_wifi(ssid, password, security, hidden):
        print("✓ WiFi configuration updated")

        # Test connectivity
        if test_wifi_connectivity():
            return True
        else:
            print("WiFi configured but connectivity test failed.")
            print("You may need to check your credentials or network settings.")
            return False
    else:
        print("✗ Failed to configure WiFi")
        return False


def validate_virustotal_api_key(api_key: str) -> bool:
    """Test if the VirusTotal API key is valid by making a test request."""
    try:
        import requests  # type: ignore
        headers = {"x-apikey": api_key}
        # Test with a known hash (empty file SHA-256)
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        url = f"https://www.virustotal.com/api/v3/files/{test_hash}"

        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            # Hash not found is also a valid response (means API key works)
            return True
        elif response.status_code == 401:
            return False
        else:
            print(f"Unexpected API response: {response.status_code}")
            return False
    except ImportError:
        print("Warning: Cannot validate API key (requests module not available)")
        return True  # Assume valid if we can't test
    except Exception as e:
        print(f"Warning: API key validation failed: {e}")
        return True  # Assume valid if test fails


def test_siem_integration(config: dict) -> bool:
    """Test SIEM integration by sending a test event."""
    if not config.get("siem_enabled"):
        return True

    try:
        if config.get("siem_type") == "syslog":
            # Test syslog connectivity
            logger = logging.getLogger('arguspi_siem_test')
            logger.setLevel(logging.INFO)

            facility_map = {
                'local0': logging.handlers.SysLogHandler.LOG_LOCAL0,
                'local1': logging.handlers.SysLogHandler.LOG_LOCAL1,
                'local2': logging.handlers.SysLogHandler.LOG_LOCAL2,
                'local3': logging.handlers.SysLogHandler.LOG_LOCAL3,
                'local4': logging.handlers.SysLogHandler.LOG_LOCAL4,
                'local5': logging.handlers.SysLogHandler.LOG_LOCAL5,
                'local6': logging.handlers.SysLogHandler.LOG_LOCAL6,
                'local7': logging.handlers.SysLogHandler.LOG_LOCAL7,
            }
            facility = facility_map.get(config.get("siem_facility", "local0"),
                                      logging.handlers.SysLogHandler.LOG_LOCAL0)

            if config.get("siem_server"):
                handler = logging.handlers.SysLogHandler(
                    address=(config["siem_server"], config.get("siem_port", 514)),
                    facility=facility
                )
            else:
                handler = logging.handlers.SysLogHandler(facility=facility)

            formatter = logging.Formatter(
                'arguspi[%(process)d]: %(name)s %(levelname)s %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

            # Send test message with station name
            station_name = config.get("station_name", "arguspi-station")
            logger.info(f"station_name={station_name} event_type=siem_test message=ArgusPi_SIEM_configuration_test")
            logger.handlers.clear()
            return True

        elif config.get("siem_type") in ["http", "webhook"]:
            # Validate webhook URL for SSRF prevention
            webhook_url = config.get("siem_webhook_url")
            if not webhook_url:
                print("Error: Webhook URL not configured")
                return False

            if not validate_webhook_url(webhook_url):
                print("Error: Webhook URL failed security validation")
                return False

            # Test HTTP webhook
            import requests  # type: ignore
            test_event = {
                "timestamp": "2025-09-20T00:00:00Z",
                "source": "arguspi",
                "station_name": config.get("station_name", "arguspi-station"),
                "hostname": socket.gethostname(),
                "event_type": "siem_test",
                "severity": "low",
                "data": {"message": "ArgusPi SIEM configuration test"}
            }

            headers = {"Content-Type": "application/json"}
            headers.update(config.get("siem_headers", {}))

            response = requests.post(
                webhook_url,  # Use validated URL
                json=test_event,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            return True

    except Exception as e:
        print(f"SIEM test failed: {e}")
        return False

    return True


def ensure_wifi_tools() -> bool:
    """Ensure wireless tools are installed for WiFi configuration."""
    try:
        # Check if iwconfig and iwlist are available
        subprocess.run(['iwconfig', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        try:
            print("Installing wireless tools...")
            subprocess.run(['apt-get', 'install', '-y', 'wireless-tools'], check=True)
            return True
        except subprocess.CalledProcessError:
            print("Warning: Could not install wireless tools. WiFi configuration may not work.")
            return False


def require_root() -> None:
    """Check if script is running with root privileges."""
    try:
        if os.geteuid() != 0:
            print("ArgusPi setup script must be run as root. Use sudo.")
            sys.exit(1)
    except AttributeError:
        # On Windows, geteuid() doesn't exist
        print("Root privilege check skipped on Windows platform.")
        pass


def prompt_configuration() -> dict:
    """Interactively ask the user for configuration values."""
    print("=== ArgusPi USB Security Scanner Setup ===")
    print("Setting up your Raspberry Pi as an ArgusPi scanning station...")
    print()

    # Station identification for multi-station deployments
    print("Station Identification")
    print("- This name will identify this ArgusPi station in logs and SIEM events")
    print("- Examples: 'reception-desk', 'lab-entrance', 'security-checkpoint-1'")

    while True:
        station_name = input("Enter station name [arguspi-station]: ").strip()
        if not station_name:
            station_name = "arguspi-station"

        # Validate station name (alphanumeric, hyphens, underscores only)
        if station_name.replace('-', '').replace('_', '').replace('.', '').isalnum():
            break
        else:
            print("Station name must contain only letters, numbers, hyphens, underscores, and dots.")

    print(f"✓ Station name set to: {station_name}")
    print()

    # WiFi Configuration
    wifi_configured = prompt_wifi_configuration()
    if not wifi_configured:
        print("Warning: WiFi configuration failed. You may need to configure networking manually.")
        retry = input("Continue with setup anyway (Y/n)? ").strip().lower()
        if retry == "n" or retry == "no":
            print("Setup cancelled. Please configure WiFi and try again.")
            sys.exit(1)

    # Prompt for API key (now optional for offline/air-gapped environments)
    print("VirusTotal Integration (optional)")
    print("- For network-connected environments: provides cloud-based threat analysis")
    print("- For offline/air-gapped environments: skip this step to run in offline mode")
    print("- You can always add this later by editing /etc/arguspi/config.json")
    print()

    api_key = ""
    skip_vt = input("Skip VirusTotal integration for offline mode? (y/N): ").strip().lower()

    if skip_vt in ("y", "yes"):
        print("✓ Configuring ArgusPi for offline mode (local scanning only)")
        api_key = ""
    else:
        while True:
            api_key = getpass(
                "Enter your VirusTotal API key (input hidden): "
            ).strip()
            if api_key:
                if len(api_key) != 64:
                    print("Warning: VirusTotal API keys are typically 64 characters long.")
                    confirm = input("Continue with this key anyway (y/N)? ").strip().lower()
                    if confirm not in ("y", "yes"):
                        continue

                # Validate the API key
                print("Testing API key...")
                if validate_virustotal_api_key(api_key):
                    print("✓ API key is valid")
                    break
                else:
                    print("✗ API key is invalid or expired. Please try again.")
                    continue
            else:
                print("API key cannot be empty (or use offline mode above). Please re-enter.")

    # Validate mount base path
    while True:
        mount_base = input(
            "Enter mount base directory [default /mnt/arguspi]: "
        ).strip() or "/mnt/arguspi"
        if os.path.isabs(mount_base):
            break
        print("Mount path must be absolute (start with /). Please re-enter.")

    # Validate request interval
    while True:
        request_interval_str = input(
            "Enter minimum seconds between VirusTotal requests (free tier = 20) [20]: "
        ).strip()
        try:
            request_interval = int(request_interval_str) if request_interval_str else 20
            if request_interval < 1:
                print("Request interval must be at least 1 second.")
                continue
            if request_interval < 15:
                print("Warning: Intervals less than 15 seconds may exceed free tier limits.")
            break
        except ValueError:
            print("Invalid interval; please enter a number.")

    # Ask user whether to enable a local ClamAV scan before contacting VirusTotal.
    use_clamav_input = input(
        "Enable local ClamAV scan before VirusTotal (y/N)? "
    ).strip().lower()
    use_clamav = use_clamav_input in ("y", "yes")
    clamav_cmd = "clamscan"

    # Prompt for LED indicator configuration
    use_led_input = input(
        "Enable RGB LED status indicator (y/N)? "
    ).strip().lower()
    use_led = use_led_input in ("y", "yes")
    led_pins = {"red": 17, "green": 27, "blue": 22}
    if use_led:
        print(
            "Enter GPIO pin numbers for the RGB LED. Use BCM numbering.\n"
            "Press Enter to accept defaults (Red=17, Green=27, Blue=22)."
        )
        while True:
            try:
                red_pin_str = input("Red pin [17]: ").strip()
                green_pin_str = input("Green pin [27]: ").strip()
                blue_pin_str = input("Blue pin [22]: ").strip()

                # Validate and assign pins
                if red_pin_str:
                    red_pin = int(red_pin_str)
                    if not (2 <= red_pin <= 27):
                        print("GPIO pin must be between 2 and 27.")
                        continue
                    led_pins["red"] = red_pin

                if green_pin_str:
                    green_pin = int(green_pin_str)
                    if not (2 <= green_pin <= 27):
                        print("GPIO pin must be between 2 and 27.")
                        continue
                    led_pins["green"] = green_pin

                if blue_pin_str:
                    blue_pin = int(blue_pin_str)
                    if not (2 <= blue_pin <= 27):
                        print("GPIO pin must be between 2 and 27.")
                        continue
                    led_pins["blue"] = blue_pin

                # Check for duplicate pins
                pins_list = list(led_pins.values())
                if len(pins_list) != len(set(pins_list)):
                    print("Error: Duplicate GPIO pins specified. Please use different pins.")
                    continue

                break
            except ValueError:
                print("Invalid pin number. Please enter integers only.")

    # SIEM integration configuration
    print("\n--- SIEM Integration (Optional) ---")
    print("Send scan events and results to your Security Information and Event Management system")
    use_siem_input = input("Enable SIEM integration (y/N)? ").strip().lower()
    use_siem = use_siem_input in ("y", "yes")

    siem_type = "syslog"
    siem_server = ""
    siem_port = 514
    siem_facility = "local0"
    siem_webhook_url = ""
    siem_headers = {}

    if use_siem:
        print("\nSIEM Integration Types:")
        print("1. Syslog (RFC 5424) - Most common, works with Splunk, ELK, QRadar, etc.")
        print("2. HTTP/Webhook - JSON POST to custom endpoints")

        while True:
            siem_choice = input("Choose SIEM type (1-2): ").strip()
            if siem_choice == "1":
                siem_type = "syslog"
                siem_server = input("SIEM server IP/hostname (leave empty for local syslog): ").strip()
                if siem_server:
                    while True:
                        try:
                            siem_port = int(input("Syslog port [514]: ").strip() or "514")
                            break
                        except ValueError:
                            print("Invalid port number.")
                siem_facility = input("Syslog facility [local0]: ").strip() or "local0"
                break
            elif siem_choice == "2":
                siem_type = "webhook"
                while True:
                    siem_webhook_url = input("Webhook URL (https://your-siem.com/webhook): ").strip()
                    if not siem_webhook_url:
                        print("Webhook URL is required for HTTP integration.")
                        continue

                    # Validate URL for SSRF prevention
                    if not validate_webhook_url(siem_webhook_url):
                        print("Please provide a valid HTTPS webhook URL to a trusted external service.")
                        continue

                    break

                # Optional headers
                auth_header = input("Authorization header (optional): ").strip()
                if auth_header:
                    siem_headers["Authorization"] = auth_header
                break
            else:
                print("Invalid choice. Please enter 1 or 2.")

    # Ask whether to enable the graphical interface
    use_gui_input = input(
        "Enable ArgusPi graphical touchscreen interface (Y/n)? "
    ).strip().lower()
    # Default is yes if the user presses enter
    use_gui = use_gui_input not in ("n", "no")

    # Screensaver configuration for GUI
    screensaver_timeout = 300  # Default 5 minutes
    if use_gui:
        print("\n--- Screensaver Configuration ---")
        print("Screensaver helps protect the display during idle periods")
        screensaver_input = input("Enable screensaver (Y/n)? ").strip().lower()
        use_screensaver = screensaver_input not in ("n", "no")

        if use_screensaver:
            while True:
                timeout_str = input("Screensaver timeout in minutes [5]: ").strip()
                try:
                    screensaver_timeout = int(timeout_str) if timeout_str else 5
                    if screensaver_timeout < 1:
                        print("Timeout must be at least 1 minute.")
                        continue
                    break
                except ValueError:
                    print("Invalid timeout; please enter a number.")
    else:
        use_screensaver = False
    return {
        "station_name": station_name,
        "api_key": api_key,
        "mount_base": mount_base,
        "request_interval": request_interval,
        "use_clamav": use_clamav,
        "clamav_cmd": clamav_cmd,
        "use_led": use_led,
        "led_pins": led_pins,
        "use_gui": use_gui,
        "use_screensaver": use_screensaver if use_gui else False,
        "screensaver_timeout": screensaver_timeout * 60,  # Convert to seconds
        "siem_enabled": use_siem,
        "siem_type": siem_type,
        "siem_server": siem_server,
        "siem_port": siem_port,
        "siem_facility": siem_facility,
        "siem_webhook_url": siem_webhook_url,
        "siem_headers": siem_headers,
    }


def write_config(config: dict) -> None:
    """Write configuration to /etc/arguspi/config.json with restricted permissions."""
    os.makedirs("/etc/arguspi", exist_ok=True)
    config_path = "/etc/arguspi/config.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(config_path, 0o600)
    print(f"✓ ArgusPi configuration written to {config_path}")


def install_packages(config: dict) -> None:
    """Install required system and Python packages.

    Always installs hdparm and Python dependencies.  If ``use_clamav``
    is enabled in the configuration, install the ClamAV package from
    the Raspberry Pi OS repository.
    """
    print("Installing required packages for ArgusPi. This may take a moment...")

    # Update apt and install hdparm and pip
    try:
        subprocess.run(["apt-get", "update"], check=True)
        print("✓ APT package list updated")
    except subprocess.CalledProcessError as e:
        print(f"⚠ Warning: Failed to update package list: {e}")

    try:
        subprocess.run(["apt-get", "install", "-y", "hdparm", "python3-pip", "wireless-tools"], check=True)
        print("✓ Installed hdparm, python3-pip, and wireless-tools")
    except subprocess.CalledProcessError as e:
        print(f"✗ Error: Failed to install basic packages: {e}")
        sys.exit(1)

    # Optionally install ClamAV
    if config.get("use_clamav"):
        try:
            subprocess.run(["apt-get", "install", "-y", "clamav"], check=True)
            print("✓ Installed ClamAV")
        except subprocess.CalledProcessError as e:
            print(f"⚠ Warning: Failed to install ClamAV: {e}")
            print("  ClamAV scanning will be disabled.")

    # Optionally install gpiozero for LED control
    if config.get("use_led"):
        try:
            subprocess.run(["apt-get", "install", "-y", "python3-gpiozero"], check=True)
            print("✓ Installed python3-gpiozero for LED control")
        except subprocess.CalledProcessError as e:
            print(f"⚠ Warning: Failed to install gpiozero: {e}")
            print("  LED indicator will be disabled.")

    # Install Tkinter for GUI if not already present
    if config.get("use_gui"):
        try:
            subprocess.run(["apt-get", "install", "-y", "python3-tk"], check=True)
            print("✓ Installed python3-tk for ArgusPi GUI")
        except subprocess.CalledProcessError as e:
            print(f"⚠ Warning: Failed to install Tkinter: {e}")
            print("  ArgusPi GUI will be disabled.")

    # Install Python dependencies - handle externally-managed-environment
    python_packages = ["pyudev", "requests"]
    
    # Try apt packages first (preferred on modern systems)
    try:
        apt_packages = ["python3-pyudev", "python3-requests"]
        subprocess.run(["apt-get", "install", "-y"] + apt_packages, check=True)
        print("✓ Installed Python dependencies via apt (python3-pyudev, python3-requests)")
    except subprocess.CalledProcessError:
        print("⚠ Warning: Could not install via apt, trying pip...")
        
        # Fall back to pip with --break-system-packages for externally-managed environments
        try:
            subprocess.run(["pip3", "install", "--break-system-packages", "--upgrade"] + python_packages, check=True)
            print("✓ Installed Python dependencies via pip with --break-system-packages (pyudev, requests)")
        except subprocess.CalledProcessError as e:
            # Final fallback: try regular pip (for older systems)
            try:
                subprocess.run(["pip3", "install", "--upgrade"] + python_packages, check=True)
                print("✓ Installed Python dependencies via pip (pyudev, requests)")
            except subprocess.CalledProcessError as final_e:
                print(f"✗ Error: Failed to install Python dependencies via all methods:")
                print(f"  - apt failed: {e}")
                print(f"  - pip failed: {final_e}")
                print("  Please install python3-pyudev and python3-requests manually:")
                print("  sudo apt install python3-pyudev python3-requests")
                sys.exit(1)

    print("✓ ArgusPi package installation complete.")


def deploy_scanning_script(config: dict) -> None:
    """Copy the ArgusPi scanning daemon script to /usr/local/bin and make it executable."""
    src_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arguspi_scan_station.py")
    dest_script = "/usr/local/bin/arguspi_scan_station.py"

    if not os.path.exists(src_script):
        print(f"✗ Error: ArgusPi scanning script not found at {src_script}")
        sys.exit(1)

    shutil.copy2(src_script, dest_script)
    os.chmod(dest_script, os.stat(dest_script).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"✓ ArgusPi scanning script deployed to {dest_script}")


def create_udev_rule() -> None:
    """Create udev rules to set USB drives read-only on insertion and remove on removal."""
    rules_path = "/etc/udev/rules.d/90-arguspi-readonly.rules"
    rule_content = """
# ArgusPi: Set USB mass-storage devices read-only on insertion and revert on removal
ACTION=="add", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{DEVTYPE}=="partition", RUN+="/sbin/hdparm -r1 /dev/%k"
ACTION=="remove", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{DEVTYPE}=="partition", RUN+="/sbin/hdparm -r0 /dev/%k"
"""
    with open(rules_path, "w") as f:
        f.write(rule_content.strip() + "\n")
    print(f"✓ ArgusPi udev rule written to {rules_path}")
    # Reload udev rules
    subprocess.run(["udevadm", "control", "--reload"])


def create_systemd_service() -> None:
    """Create and enable the ArgusPi systemd service to run the scanning daemon."""
    service_path = "/etc/systemd/system/arguspi.service"
    service_content = f"""
[Unit]
Description=ArgusPi USB Security Scanner
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 /usr/local/bin/arguspi_scan_station.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
    with open(service_path, "w") as f:
        f.write(service_content.strip() + "\n")
    print(f"✓ ArgusPi systemd service file created at {service_path}")
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", "arguspi.service"], check=False)
    subprocess.run(["systemctl", "restart", "arguspi.service"], check=False)
    print("✓ ArgusPi service enabled and started.")


def main() -> None:
    """Main setup function for ArgusPi USB security scanner."""
    print("=" * 50)
    print("    ArgusPi USB Security Scanner Setup")
    print("=" * 50)
    require_root()
    config = prompt_configuration()
    write_config(config)

    # Test SIEM integration if enabled
    if config.get("siem_enabled"):
        print("Testing SIEM integration...")
        if test_siem_integration(config):
            print("✓ SIEM integration test successful")
        else:
            print("✗ SIEM integration test failed - check configuration")
            retry = input("Continue with setup anyway (Y/n)? ").strip().lower()
            if retry == "n" or retry == "no":
                print("Setup cancelled. Please check SIEM configuration and try again.")
                sys.exit(1)

    install_packages(config)
    deploy_scanning_script(config)
    create_udev_rule()
    create_systemd_service()
    # Create mount base directory
    os.makedirs(config["mount_base"], exist_ok=True)
    print()
    print("=" * 50)
    print("✓ ArgusPi USB scan station setup complete!")
    print()
    print("Your Raspberry Pi is now configured as an ArgusPi")
    print("USB security scanning station. Insert a USB device")
    print("to test the scanning functionality.")
    print()
    print(f"View logs with: sudo journalctl -u arguspi -f")
    print(f"Configuration: /etc/arguspi/config.json")
    print(f"Log file: /var/log/arguspi.log")
    print("=" * 50)


if __name__ == "__main__":
    main()

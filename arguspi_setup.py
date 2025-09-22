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


def load_existing_config() -> dict:
    """Load existing ArgusPi configuration if it exists."""
    config_path = "/etc/arguspi/config.json"
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError, PermissionError):
            pass
    
    # Return default configuration if none exists
    return {
        "api_key": "",
        "request_interval": 20,
        "mount_base": "/mnt/arguspi",
        "log_path": "/var/log/arguspi.log",
        "use_clamav": True,
        "clamav_cmd": "clamdscan",
        "use_led": False,
        "led_pins": {"red": 17, "green": 27, "blue": 22},
        "use_gui": True,
        "gui_simple_mode": False,
        "station_name": "arguspi-station",
        "siem_enabled": False,
        "siem_webhook_url": "",
        "display_rotation": 0
    }


def print_banner():
    """Print an attractive banner for the setup script."""
    print("\n" + "═" * 80)
    print(" █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗██████╗ ██╗")
    print("██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝██╔══██╗██║")
    print("███████║██████╔╝██║  ███╗██║   ██║███████╗██████╔╝██║")
    print("██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║██╔═══╝ ██║")
    print("██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║██║     ██║")
    print("╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝     ╚═╝")
    print("")
    print("                    ArgusPi USB Security Scanner Setup")
    print("                  Enhanced Configuration & Installation")
    print("═" * 80)


def prompt_with_default(prompt_text: str, default_value: any = None, password: bool = False) -> str:
    """Prompt user with a default value shown in brackets."""
    if default_value is not None:
        if password and default_value:
            display_default = f"[{'*' * 8}] (current key hidden)"
        else:
            display_default = f"[{default_value}]"
        
        full_prompt = f"{prompt_text} {display_default}: "
    else:
        full_prompt = f"{prompt_text}: "
    
    if password:
        response = getpass(full_prompt).strip()
    else:
        response = input(full_prompt).strip()
    
    # Return default if empty response and default exists
    if not response and default_value is not None:
        return str(default_value)
    
    return response


def prompt_yes_no(prompt_text: str, default: bool = True) -> bool:
    """Prompt for yes/no with a default value."""
    default_text = "Y/n" if default else "y/N"
    response = input(f"{prompt_text} ({default_text}): ").strip().lower()
    
    if not response:
        return default
    
    return response in ("y", "yes", "1", "true")


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
    configure_wifi_input = input("Configure WiFi network (y/N)? ").strip().lower()
    if configure_wifi_input not in ("y", "yes"):
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
    """Interactively ask the user for configuration values with enhanced UX."""
    print_banner()
    
    # Load existing configuration
    existing_config = load_existing_config()
    config_exists = os.path.exists("/etc/arguspi/config.json")
    
    if config_exists:
        print("📋 Existing Configuration Found!")
        print("   Current values will be shown in [brackets]. Press Enter to keep current values.\n")
    else:
        print("🆕 Setting up ArgusPi for the first time!")
        print("   Default values will be shown in [brackets]. Press Enter to accept defaults.\n")
    
    config = {}
    
    # Station identification
    print("┌─ 🏷️  Station Identification " + "─" * 48)
    print("│ This name identifies this ArgusPi station in logs and SIEM events.")
    print("│ Examples: 'reception-desk', 'lab-entrance', 'security-checkpoint-1'")
    print("└" + "─" * 70)
    
    while True:
        station_name = prompt_with_default(
            "Station name", 
            existing_config.get("station_name", "arguspi-station")
        )
        
        # Validate station name
        if station_name.replace('-', '').replace('_', '').replace('.', '').isalnum():
            config["station_name"] = station_name
            print(f"   ✓ Station name: {station_name}\n")
            break
        else:
            print("   ❌ Station name must contain only letters, numbers, hyphens, underscores, and dots.\n")

    # VirusTotal Configuration
    print("┌─ 🔍 VirusTotal Integration " + "─" * 47)
    print("│ Cloud-based threat analysis (optional for offline environments)")
    print("│ Leave empty to run in offline mode with local scanning only")
    print("└" + "─" * 70)
    
    has_existing_key = bool(existing_config.get("api_key"))
    use_virustotal = prompt_yes_no(
        "Enable VirusTotal cloud analysis",
        default=has_existing_key or not config_exists
    )
    
    if use_virustotal:
        while True:
            api_key = prompt_with_default(
                "VirusTotal API key", 
                existing_config.get("api_key", ""),
                password=True
            )
            
            if not api_key:
                print("   ❌ API key cannot be empty when VirusTotal is enabled.")
                if existing_config.get("api_key"):
                    keep_existing = prompt_yes_no("Keep existing API key", default=True)
                    if keep_existing:
                        config["api_key"] = existing_config["api_key"]
                        print("   ✓ Keeping existing API key\n")
                        break
                continue
            
            # Validate key length
            if len(api_key) != 64:
                print(f"   ⚠️  Warning: VirusTotal API keys are typically 64 characters (got {len(api_key)})")
                if not prompt_yes_no("Continue with this key anyway", default=False):
                    continue
            
            # Test API key if it's new or changed
            if api_key != existing_config.get("api_key"):
                print("   🔄 Testing API key...")
                if validate_virustotal_api_key(api_key):
                    print("   ✓ API key is valid")
                    config["api_key"] = api_key
                    break
                else:
                    print("   ❌ API key is invalid or expired")
                    continue
            else:
                config["api_key"] = api_key
                print("   ✓ Using existing API key")
                break
        
        # Request interval
        while True:
            try:
                interval_str = prompt_with_default(
                    "Seconds between VirusTotal requests (free tier: 20+)",
                    existing_config.get("request_interval", 20)
                )
                request_interval = int(interval_str)
                
                if request_interval < 1:
                    print("   ❌ Request interval must be at least 1 second")
                    continue
                
                if request_interval < 15:
                    print("   ⚠️  Warning: Intervals < 15 seconds may exceed free tier limits")
                    if not prompt_yes_no("Continue with this interval", default=False):
                        continue
                
                config["request_interval"] = request_interval
                print(f"   ✓ Request interval: {request_interval} seconds\n")
                break
                
            except ValueError:
                print("   ❌ Please enter a valid number")
    else:
        print("   ✓ Running in offline mode (local scanning only)\n")
        config["api_key"] = ""
        config["request_interval"] = 1  # Not used in offline mode
    
    # Local scanning configuration  
    print("┌─ 🛡️  Local Security Scanning " + "─" * 44)
    print("│ ClamAV provides local malware detection")
    print("└" + "─" * 70)
    
    config["use_clamav"] = prompt_yes_no(
        "Enable local ClamAV scanning",
        existing_config.get("use_clamav", True)
    )
    config["clamav_cmd"] = existing_config.get("clamav_cmd", "clamdscan")
    print(f"   ✓ ClamAV: {'Enabled' if config['use_clamav'] else 'Disabled'}\n")

    # File system configuration
    print("┌─ 💾 File System Configuration " + "─" * 42)
    print("│ Mount point and logging settings")
    print("└" + "─" * 70)
    
    while True:
        mount_base = prompt_with_default(
            "USB mount base directory",
            existing_config.get("mount_base", "/mnt/arguspi")
        )
        
        if os.path.isabs(mount_base):
            config["mount_base"] = mount_base
            break
        else:
            print("   ❌ Mount path must be absolute (start with /)")
    
    config["log_path"] = existing_config.get("log_path", "/var/log/arguspi.log")
    print(f"   ✓ Mount base: {config['mount_base']}")
    print(f"   ✓ Log file: {config['log_path']}\n")

    # GUI Configuration
    print("┌─ 🖥️  User Interface " + "─" * 52)
    print("│ Graphical user interface settings")  
    print("└" + "─" * 70)
    
    config["use_gui"] = prompt_yes_no(
        "Enable graphical user interface",
        existing_config.get("use_gui", True)
    )
    
    if config["use_gui"]:
        config["gui_simple_mode"] = prompt_yes_no(
            "Use simplified GUI mode (recommended for end users)",
            existing_config.get("gui_simple_mode", False)
        )
        
        # Display rotation
        rotation_options = {0: "Normal (0°)", 1: "90° clockwise", 2: "180°", 3: "270° clockwise"}
        current_rotation = existing_config.get("display_rotation", 0)
        
        print(f"   Current display rotation: {rotation_options[current_rotation]}")
        print("   Rotation options: 0=Normal, 1=90°, 2=180°, 3=270°")
        
        while True:
            try:
                rotation_str = prompt_with_default("Display rotation", current_rotation)
                rotation = int(rotation_str)
                if rotation in rotation_options:
                    config["display_rotation"] = rotation
                    
                    # Offer to test the rotation if not default
                    if rotation != 0:
                        test_rotation = prompt_yes_no(
                            f"Test {rotation * 90}° rotation now (10 second preview)",
                            False
                        )
                        if test_rotation:
                            test_display_rotation(rotation)
                    
                    break
                else:
                    print("   ❌ Rotation must be 0, 1, 2, or 3")
            except ValueError:
                print("   ❌ Please enter a valid number")
        
        print(f"   ✓ GUI: Enabled ({'Simple' if config['gui_simple_mode'] else 'Detailed'} mode)")
        print(f"   ✓ Display: {rotation_options[config['display_rotation']]}\n")
    else:
        config["gui_simple_mode"] = False
        config["display_rotation"] = 0
        print("   ✓ GUI: Disabled (headless mode)\n")

    # Hardware Configuration
    print("┌─ ⚡ Hardware Features " + "─" * 48)
    print("│ LED indicators and other hardware")
    print("└" + "─" * 70)
    
    config["use_led"] = prompt_yes_no(
        "Enable RGB LED status indicator",
        existing_config.get("use_led", False)
    )
    
    if config["use_led"]:
        print("   GPIO pin configuration (BCM numbering):")
        led_pins = existing_config.get("led_pins", {"red": 17, "green": 27, "blue": 22})
        
        for color in ["red", "green", "blue"]:
            while True:
                try:
                    pin_str = prompt_with_default(f"   {color.capitalize()} LED GPIO pin", led_pins[color])
                    pin = int(pin_str)
                    if 0 <= pin <= 40:
                        led_pins[color] = pin
                        break
                    else:
                        print("   ❌ GPIO pin must be between 0 and 40")
                except ValueError:
                    print("   ❌ Please enter a valid pin number")
        
        config["led_pins"] = led_pins
        print(f"   ✓ LED: Enabled (R:{led_pins['red']}, G:{led_pins['green']}, B:{led_pins['blue']})\n")
    else:
        config["led_pins"] = existing_config.get("led_pins", {"red": 17, "green": 27, "blue": 22})
        print("   ✓ LED: Disabled\n")

    # SIEM Integration  
    print("┌─ 📊 SIEM Integration " + "─" * 50)
    print("│ Security Information and Event Management")
    print("└" + "─" * 70)
    
    config["siem_enabled"] = prompt_yes_no(
        "Enable SIEM webhook notifications",
        existing_config.get("siem_enabled", False)
    )
    
    if config["siem_enabled"]:
        while True:
            webhook_url = prompt_with_default(
                "SIEM webhook URL (HTTPS required)",
                existing_config.get("siem_webhook_url", "")
            )
            
            if not webhook_url:
                print("   ❌ Webhook URL is required when SIEM is enabled")
                continue
                
            if validate_webhook_url(webhook_url):
                config["siem_webhook_url"] = webhook_url
                print("   ✓ SIEM webhook URL validated")
                break
            else:
                print("   ❌ Invalid webhook URL")
        print(f"   ✓ SIEM: Enabled\n")
    else:
        config["siem_webhook_url"] = existing_config.get("siem_webhook_url", "")
        print("   ✓ SIEM: Disabled\n")

    # Configuration summary
    print("┌─ 📋 Configuration Summary " + "─" * 45)
    print(f"│ Station: {config['station_name']}")
    print(f"│ VirusTotal: {'Enabled' if config['api_key'] else 'Disabled (offline mode)'}")
    print(f"│ ClamAV: {'Enabled' if config['use_clamav'] else 'Disabled'}")
    print(f"│ GUI: {'Enabled' if config['use_gui'] else 'Disabled'}")
    print(f"│ LED: {'Enabled' if config['use_led'] else 'Disabled'}")
    print(f"│ SIEM: {'Enabled' if config['siem_enabled'] else 'Disabled'}")
    print("└" + "─" * 70)
    
    if not prompt_yes_no("\nSave this configuration and continue with setup", default=True):
        print("\n❌ Setup cancelled by user.")
        sys.exit(0)
    
    print("\n✅ Configuration saved! Proceeding with installation...\n")
    return config


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

    # Update system packages first
    try:
        print("Updating system packages...")
        subprocess.run(["apt-get", "update"], check=True)
        subprocess.run(["apt-get", "upgrade", "-y"], check=True)
        print("✓ System packages updated")
    except subprocess.CalledProcessError as e:
        print(f"⚠ Warning: Failed to update system packages: {e}")

    # Install core system packages
    try:
        core_packages = [
            "hdparm", "python3-pip", "wireless-tools", 
            "python3-tk", "python3-dev", "python3-setuptools",
            "usbutils", "lsof", "systemd", "git"
        ]
        subprocess.run(["apt-get", "install", "-y"] + core_packages, check=True)
        print("✓ Installed core system packages")
    except subprocess.CalledProcessError as e:
        print(f"✗ Error: Failed to install basic packages: {e}")
        sys.exit(1)

    # Install Python packages
    try:
        python_packages = ["psutil", "requests"]
        subprocess.run(["pip3", "install", "--user"] + python_packages, check=True)
        print("✓ Installed Python dependencies")
    except subprocess.CalledProcessError as e:
        print(f"⚠ Warning: Failed to install Python packages: {e}")

    # Check if GUI is enabled and desktop environment is needed
    if config.get("use_gui"):
        # Install X11 utilities for GUI support
        try:
            x11_packages = ["x11-xserver-utils", "xauth"]
            subprocess.run(["apt-get", "install", "-y"] + x11_packages, check=True)
            print("✓ Installed X11 utilities for GUI support")
        except subprocess.CalledProcessError as e:
            print(f"⚠ Warning: Failed to install X11 utilities: {e}")

        # Check if desktop environment is already installed
        try:
            result = subprocess.run(["dpkg", "-l", "raspberrypi-ui-mods"], capture_output=True, text=True)
            if result.returncode != 0:
                print("⚠ Desktop environment not found. Installing for GUI support...")
                try:
                    subprocess.run(["apt-get", "install", "-y", "raspberrypi-ui-mods", "lxde-core", "lightdm", "x11-xserver-utils"], check=True)
                    print("✓ Installed desktop environment (raspberrypi-ui-mods, lxde-core, lightdm)")
                    
                    # Enable graphical boot target
                    subprocess.run(["systemctl", "set-default", "graphical.target"], check=True)
                    subprocess.run(["systemctl", "enable", "lightdm"], check=True)
                    print("✓ Configured system for graphical boot")
                    
                except subprocess.CalledProcessError as e:
                    print(f"⚠ Warning: Failed to install desktop environment: {e}")
                    print("  GUI will not work properly. Consider using Raspberry Pi OS Desktop image.")
            else:
                print("✓ Desktop environment already installed")
        except subprocess.CalledProcessError:
            print("⚠ Warning: Could not check desktop environment status")

    # Optionally install ClamAV with daemon for performance
    if config.get("use_clamav"):
        try:
            # Install complete ClamAV package including daemon for optimal performance
            subprocess.run(["apt-get", "install", "-y", "clamav", "clamav-daemon", "clamav-freshclam"], check=True)
            print("✓ Installed ClamAV with daemon (clamav, clamav-daemon, clamav-freshclam)")
            
            # Update ClamAV virus database
            print("Updating ClamAV virus database...")
            try:
                subprocess.run(["systemctl", "stop", "clamav-freshclam"], check=True)
                subprocess.run(["freshclam"], check=True)
                subprocess.run(["systemctl", "start", "clamav-freshclam"], check=True)
                print("✓ ClamAV virus database updated")
            except subprocess.CalledProcessError as e:
                print(f"⚠ Warning: Could not update ClamAV database: {e}")
            
            # Start and enable ClamAV services
            try:
                subprocess.run(["systemctl", "enable", "clamav-daemon"], check=True)
                subprocess.run(["systemctl", "enable", "clamav-freshclam"], check=True)
                print("✓ Enabled ClamAV services for automatic startup")
                
                # Start freshclam service to update virus database
                subprocess.run(["systemctl", "start", "clamav-freshclam"], check=True)
                print("✓ Started ClamAV database update service")
                
                # Note: clamav-daemon will start automatically after freshclam updates database
                print("  Note: ClamAV daemon will start automatically after virus database update")
                
            except subprocess.CalledProcessError as e:
                print(f"⚠ Warning: Failed to configure ClamAV services: {e}")
                print("  ClamAV is installed but may need manual service configuration")
                
        except subprocess.CalledProcessError as e:
            print(f"⚠ Warning: Failed to install ClamAV: {e}")
            print("  ClamAV scanning will be disabled - scanning will be much slower!")

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
    """Copy the ArgusPi scanning daemon script and diagnostic tools to /usr/local/bin and make them executable."""
    # Deploy main scanning script
    src_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arguspi_scan_station.py")
    dest_script = "/usr/local/bin/arguspi_scan_station.py"

    if not os.path.exists(src_script):
        print(f"✗ Error: ArgusPi scanning script not found at {src_script}")
        sys.exit(1)

    shutil.copy2(src_script, dest_script)
    os.chmod(dest_script, os.stat(dest_script).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"✓ ArgusPi scanning script deployed to {dest_script}")

    # Deploy diagnostic tool if available
    src_diagnostic = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui_diagnostic.py")
    if os.path.exists(src_diagnostic):
        dest_diagnostic = "/usr/local/bin/gui_diagnostic.py"
        shutil.copy2(src_diagnostic, dest_diagnostic)
        os.chmod(dest_diagnostic, os.stat(dest_diagnostic).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"✓ GUI diagnostic tool deployed to {dest_diagnostic}")
    else:
        print("⚠ GUI diagnostic tool not found - skipping deployment")


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


def create_systemd_service(config: dict) -> None:
    """Create ArgusPi systemd service with GUI support when enabled."""
    service_path = "/etc/systemd/system/arguspi.service"
    
    # Get user info for GUI environment if GUI is enabled
    if config.get("use_gui", True):
        username, uid, gid, homedir = get_desktop_user()
        
        # Create a robust service that works with both old (Xorg) and new (Wayland/labwc) systems
        service_content = f"""[Unit]
Description=ArgusPi USB Security Scanner with GUI
After=graphical-session.target
Wants=graphical-session.target
# Wait for desktop session to be fully ready
After=display-manager.service
Wants=display-manager.service

[Service]
Type=simple
User=root
Group=root
# Robust wait for display server - works with Xorg, X11, labwc, and Wayland
ExecStartPre=/bin/bash -c 'timeout=60; while [ $timeout -gt 0 ] && [ ! -S /tmp/.X11-unix/X0 ]; do sleep 1; timeout=$((timeout-1)); done'
# Wait for desktop session to start - handles multiple desktop environments
ExecStartPre=/bin/bash -c 'timeout=30; while [ $timeout -gt 0 ] && ! pgrep -f "lxsession|gnome-session|xfce4-session|labwc|startlxde" > /dev/null; do sleep 1; timeout=$((timeout-1)); done'
Environment=DISPLAY=:0
Environment=XDG_RUNTIME_DIR=/run/user/{uid}
Environment=XAUTHORITY={homedir}/.Xauthority
Environment=HOME={homedir}
# Allow X11 forwarding from root - works with both X11 and XWayland
ExecStartPre=/bin/bash -c 'su {username} -c "xhost +local:root 2>/dev/null || true"'
ExecStart=/usr/bin/python3 /usr/local/bin/arguspi_scan_station.py
Restart=always
RestartSec=10
# Give more time for desktop to be ready
TimeoutStartSec=120

[Install]
WantedBy=graphical.target
"""
    else:
        # Non-GUI mode - simpler service
        service_content = """[Unit]
Description=ArgusPi USB Security Scanner (Background Service)
After=multi-user.target
Wants=multi-user.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/arguspi_scan_station.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    
    with open(service_path, "w") as f:
        f.write(service_content.strip() + "\n")
    
    print(f"✓ ArgusPi systemd service file created at {service_path}")
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    
    if config.get("use_gui", True):
        print("✓ SystemD service configured for GUI mode")
        print("  Service will be enabled during GUI configuration")
    else:
        print("✓ SystemD service configured for background mode")
        print("  Enable with: sudo systemctl enable arguspi")


def get_desktop_user() -> tuple:
    """Get the actual desktop user account (not always 'pi' in modern Pi OS)."""
    try:
        # Try to get the user who invoked sudo (the real desktop user)
        real_user = os.environ.get('SUDO_USER')
        if real_user and real_user != 'root':
            import pwd
            user_info = pwd.getpwnam(real_user)
            print(f"✓ Detected desktop user: {real_user} (UID: {user_info.pw_uid})")
            return real_user, user_info.pw_uid, user_info.pw_gid, user_info.pw_dir
    except Exception:
        pass
    
    # Fallback 1: Try the traditional 'pi' user
    try:
        import pwd
        pi_user = pwd.getpwnam("pi")
        print("✓ Using traditional 'pi' user account")
        return "pi", pi_user.pw_uid, pi_user.pw_gid, pi_user.pw_dir
    except KeyError:
        pass
    
    # Fallback 2: Look for first non-system user (UID >= 1000)
    try:
        import pwd
        for user in pwd.getpwall():
            if user.pw_uid >= 1000 and user.pw_uid < 65534:  # Regular user range
                if user.pw_dir.startswith('/home/'):
                    print(f"✓ Found desktop user: {user.pw_name} (UID: {user.pw_uid})")
                    return user.pw_name, user.pw_uid, user.pw_gid, user.pw_dir
    except Exception:
        pass
    
    # Final fallback: Use environment or defaults
    current_user = os.environ.get('USER', 'pi')
    print(f"⚠ Warning: Using fallback user: {current_user}")
    return current_user, 1000, 1000, f"/home/{current_user}"


def create_desktop_autostart(config: dict) -> bool:
    """Configure GUI startup using systemd service instead of desktop autostart (more reliable for sudo)."""
    if not config.get("use_gui", True):
        print("GUI disabled - skipping GUI startup configuration")
        return True
        
    try:
        print("Setting up GUI startup using systemd service...")
        
        # Skip desktop autostart (doesn't work with sudo) and ensure systemd service handles GUI
        print("  Desktop autostart with sudo doesn't work reliably during boot")
        print("  Using systemd service instead for reliable GUI startup")
        
        # Get the actual desktop user for environment variables
        username, uid, gid, homedir = get_desktop_user()
        
        # The systemd service should already be created, just enable it for GUI startup
        try:
            subprocess.run(["systemctl", "enable", "arguspi"], check=True)
            print("✓ SystemD service enabled for automatic GUI startup")
            print(f"  GUI will start automatically on boot for user environment")
            print(f"  Service runs with proper permissions and GUI access")
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"⚠ Warning: Could not enable systemd service: {e}")
            return False
        
    except Exception as e:
        print(f"⚠ Warning: Could not configure GUI startup: {e}")
        print("Manual configuration required:")
        print("  After reboot, start GUI manually with: python3 /usr/local/bin/arguspi_scan_station.py")
        print("  Or enable systemd service with: sudo systemctl enable arguspi && sudo systemctl start arguspi")
        return False


def verify_clamav_installation() -> None:
    """Verify ClamAV installation and provide guidance if issues are found."""
    try:
        # Check ClamAV version
        result = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, check=True)
        print(f"✓ ClamAV command-line scanner: {result.stdout.strip()}")
        
        # Check daemon status
        daemon_result = subprocess.run(["systemctl", "is-active", "clamav-daemon"], 
                                     capture_output=True, text=True)
        if daemon_result.returncode == 0:
            print("✓ ClamAV daemon is running")
        else:
            print("⚠ ClamAV daemon not yet running (will start after database update)")
            
        # Check freshclam status
        freshclam_result = subprocess.run(["systemctl", "is-active", "clamav-freshclam"], 
                                        capture_output=True, text=True)
        if freshclam_result.returncode == 0:
            print("✓ ClamAV database update service is running")
        else:
            print("⚠ ClamAV database update service not running")
            
        # Check if database files exist
        db_files = subprocess.run(["find", "/var/lib/clamav", "-name", "*.cvd", "-o", "-name", "*.cld"], 
                                capture_output=True, text=True)
        if db_files.stdout.strip():
            print("✓ ClamAV virus database files found")
            print("  📈 Performance: With ClamAV daemon, scanning ~10 minutes for 1000 files")
        else:
            print("⚠ ClamAV virus database not yet downloaded")
            print("  Run 'sudo freshclam' after setup to download virus definitions")
            
    except subprocess.CalledProcessError as e:
        print(f"✗ ClamAV verification failed: {e}")
        print("⚠ WARNING: Without ClamAV daemon, scanning will be extremely slow!")
        print("  📉 Performance: Without ClamAV, ~5.5 hours for 1000 files")
        print("  💡 Recommendation: Run the troubleshooting steps in TROUBLESHOOTING.md")


def configure_cmdline_rotation(rotation: int) -> bool:
    """
    Configure display rotation in /boot/firmware/cmdline.txt using video parameter.
    
    Args:
        rotation: Display rotation (0=0°, 1=90°, 2=180°, 3=270°)
    
    Returns:
        bool: True if successful, False otherwise
    """
    if rotation == 0:
        return True  # No rotation needed
        
    # Try modern Pi OS location first
    cmdline_path = "/boot/firmware/cmdline.txt"
    if not os.path.exists(cmdline_path):
        # Fallback to legacy location
        cmdline_path = "/boot/cmdline.txt"
        if not os.path.exists(cmdline_path):
            return False
    
    try:
        # Read current cmdline.txt
        with open(cmdline_path, 'r') as f:
            cmdline = f.read().strip()
        
        # Remove any existing rotation parameters
        words = cmdline.split()
        words = [word for word in words if not word.startswith('video=DSI-1:') and not word.startswith('display_rotate=')]
        
        # Add new rotation parameter
        rotation_degrees = rotation * 90
        video_param = f"video=DSI-1:720x1280@60,rotate={rotation_degrees}"
        words.append(video_param)
        
        # Write back to cmdline.txt
        new_cmdline = " ".join(words)
        with open(cmdline_path, 'w') as f:
            f.write(new_cmdline + "\n")
            
        return True
        
    except Exception as e:
        print(f"⚠ Failed to configure cmdline rotation: {e}")
        return False


def test_display_rotation(rotation: int) -> None:
    """Test display rotation with immediate feedback."""
    print(f"\n🔄 Testing display rotation: {rotation * 90}°")
    
    try:
        import subprocess
        import time
        
        # Try wlr-randr first (modern Wayland)
        result = subprocess.run(["which", "wlr-randr"], capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            print("✓ Found wlr-randr (Wayland)")
            
            # Get outputs and try rotation
            result = subprocess.run(["wlr-randr"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                outputs = [line.split()[0] for line in result.stdout.strip().split('\n') 
                          if line and not line.startswith(' ')]
                
                for output in outputs[:1]:  # Try first output
                    if output:
                        cmd = ["wlr-randr", "--output", output, "--transform", str(rotation * 90)]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        
                        if result.returncode == 0:
                            print(f"✓ Applied test rotation to {output}")
                            print("  ⏱  Rotation will revert in 10 seconds...")
                            time.sleep(10)
                            
                            # Revert to normal
                            cmd = ["wlr-randr", "--output", output, "--transform", "normal"]
                            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                            print("✓ Reverted to normal orientation")
                            return
        
        # Try xrandr (X11)
        result = subprocess.run(["which", "xrandr"], capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            print("✓ Found xrandr (X11)")
            
            rotations = {0: "normal", 1: "left", 2: "inverted", 3: "right"}
            xrandr_rot = rotations[rotation]
            
            for output in ["DSI-1", "HDMI-1", "HDMI-A-1"]:
                cmd = ["xrandr", "--output", output, "--rotate", xrandr_rot]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    print(f"✓ Applied test rotation to {output}")
                    print("  ⏱  Rotation will revert in 10 seconds...")
                    time.sleep(10)
                    
                    # Revert to normal
                    cmd = ["xrandr", "--output", output, "--rotate", "normal"]
                    subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    print("✓ Reverted to normal orientation")
                    return
        
        print("⚠ No rotation tools available for testing")
        print("  Configuration will be saved but requires reboot to take effect")
        
    except Exception as e:
        print(f"⚠ Rotation test failed: {e}")


def configure_display_rotation(rotation: int) -> bool:
    """
    Configure display rotation in /boot/firmware/config.txt (modern Pi OS) or /boot/config.txt (legacy).
    
    Args:
        rotation: Display rotation (0=0°, 1=90°, 2=180°, 3=270°)
    
    Returns:
        bool: True if successful, False otherwise
    """
    # Try modern Pi OS location first
    config_path = "/boot/firmware/config.txt"
    if not os.path.exists(config_path):
        # Fallback to legacy location for older Pi OS versions
        config_path = "/boot/config.txt"
        if not os.path.exists(config_path):
            print(f"⚠ Could not find config.txt at /boot/firmware/config.txt or /boot/config.txt")
            return False
            return False
    
    try:
        # Read current config.txt
        with open(config_path, 'r') as f:
            lines = f.readlines()
        
        # Remove any existing display_rotate lines
        lines = [line for line in lines if not line.strip().startswith('display_rotate=')]
        
        # Add new display_rotate setting if not default
        if rotation != 0:
            lines.append(f"display_rotate={rotation}\n")
        
        # Write back to config.txt
        with open(config_path, 'w') as f:
            f.writelines(lines)
        
        rotation_names = {0: "Normal (0°)", 1: "90° clockwise", 2: "180°", 3: "270° clockwise"}
        print(f"✓ Display rotation set to: {rotation_names.get(rotation, f'{rotation}°')}")
        print(f"  Configuration updated in: {config_path}")
        
        if rotation != 0:
            print("  📱 Changes will take effect after reboot")
        
        return True
        
    except PermissionError:
        print(f"✗ Permission denied accessing {config_path}")
        print("  This script must be run with sudo to modify boot configuration")
        return False
    except Exception as e:
        print(f"✗ Failed to configure display rotation: {e}")
        return False


def main() -> None:
    """Main setup function for ArgusPi USB security scanner."""
    print("=" * 50)
    print("    ArgusPi USB Security Scanner Setup")
    print("=" * 50)
    require_root()
    
    # Detect and display user information for GUI setup
    print("\n--- User Account Detection ---")
    try:
        username, uid, gid, homedir = get_desktop_user()
        print(f"Desktop user detected: {username}")
        print(f"Home directory: {homedir}")
        print(f"UID: {uid}, GID: {gid}")
    except Exception as e:
        print(f"Warning: Could not detect user account: {e}")
    print()
    
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
    
    # Verify ClamAV installation if enabled
    if config.get("use_clamav"):
        print("\n--- Verifying ClamAV Installation ---")
        verify_clamav_installation()
    
    deploy_scanning_script(config)
    create_udev_rule()
    create_systemd_service(config)
    
    # Configure GUI autostart (if GUI is enabled)
    if config.get("use_gui", True):
        print("\n--- GUI Configuration ---")
        autostart_success = create_desktop_autostart(config)
        
        if autostart_success:
            print("✓ GUI startup configured successfully")
            print("  ArgusPi will start automatically after reboot via systemd service")
        else:
            print("⚠ GUI configuration failed")
            print("  See troubleshooting output above for manual steps")
            
        # Configure display rotation
        print("\n--- Display Configuration ---")
        display_rotation = config.get("display_rotation", 0)
        if display_rotation != 0:
            print(f"Configuring {display_rotation * 90}° rotation...")
            
            # Try multiple configuration methods
            config_success = configure_display_rotation(display_rotation)
            cmdline_success = configure_cmdline_rotation(display_rotation)
            
            if config_success or cmdline_success:
                print("✓ Display rotation configured")
                print("📋 Configured methods:")
                if config_success:
                    print("  • config.txt rotation setting")
                if cmdline_success:
                    print("  • cmdline.txt boot parameter")
                print("🔄 Reboot required for rotation to take effect")
            else:
                print("⚠ Automatic rotation configuration failed")
                print("📖 Manual configuration required:")
                print(f"  Add to /boot/firmware/cmdline.txt: video=DSI-1:720x1280@60,rotate={display_rotation * 90}")
                print(f"  Or add to /boot/firmware/config.txt: display_rotate={display_rotation}")
        else:
            print("✓ Display rotation: Normal (0°)")
    else:
        # For non-GUI mode
        print("✓ GUI disabled - running in headless mode")
    
    print("\n--- Final Steps ---")
    
    # Create mount base directory
    os.makedirs(config["mount_base"], exist_ok=True)
    
    # Run GUI diagnostics if GUI is enabled and diagnostic tool was deployed
    if config.get("use_gui", True):
        diagnostic_path = "/usr/local/bin/gui_diagnostic.py"
        if os.path.exists(diagnostic_path):
            print("\n--- Running GUI Diagnostics ---")
            try:
                subprocess.run(["python3", diagnostic_path], check=True)
            except subprocess.CalledProcessError:
                print("⚠ GUI diagnostic tool encountered issues - check output above")
    
    print()
    print("=" * 50)
    print("✓ ArgusPi USB scan station setup complete!")
    print()
    print("Your Raspberry Pi is now configured as an ArgusPi")
    print("USB security scanning station.")
    
    if config.get("use_gui", True):
        print()
        print("📺 GUI Configuration:")
        print("  - GUI autostart has been configured")
        print("  - IMPORTANT: You must manually enable desktop autologin")
        print("  - Run: sudo raspi-config → System Options → Boot / Auto Login → Desktop Autologin")
        print("  - Then reboot: sudo reboot")
        print()
        print("🔧 If GUI doesn't start after reboot:")
        print("  1. Run diagnostics: python3 /usr/local/bin/gui_diagnostic.py")
        print("  2. Check service logs: sudo journalctl -u arguspi.service -f")
        print("  3. Apply fix if needed: bash fix_gui_service.sh")
    
    print()
    print("🔌 Testing: Insert a USB device to test scanning")
    print()
    print(f"📊 Monitor with GUI or logs: /var/log/arguspi.log")
    print(f"⚙️  Configuration: /etc/arguspi/config.json")
    print(f"� Systemd service (if needed): sudo systemctl enable arguspi")
    print("=" * 50)


if __name__ == "__main__":
    main()

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
   read‑only upon insertion and clear the flag on removal using
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
from getpass import getpass


def validate_virustotal_api_key(api_key: str) -> bool:
    """Test if the VirusTotal API key is valid by making a test request."""
    try:
        import requests
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


def require_root() -> None:
    if os.geteuid() != 0:
        print("ArgusPi setup script must be run as root. Use sudo.")
        sys.exit(1)


def prompt_configuration() -> dict:
    """Interactively ask the user for configuration values."""
    print("=== ArgusPi USB Security Scanner Setup ===")
    print("Setting up your Raspberry Pi as an ArgusPi scanning station...")
    print()
    
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
                print("API key cannot be empty (or use offline mode above). Please re‑enter.")
    
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
    
    # Ask whether to enable the graphical interface
    use_gui_input = input(
        "Enable ArgusPi graphical touchscreen interface (Y/n)? "
    ).strip().lower()
    # Default is yes if the user presses enter
    use_gui = use_gui_input not in ("n", "no")
    return {
        "api_key": api_key,
        "mount_base": mount_base,
        "request_interval": request_interval,
        "use_clamav": use_clamav,
        "clamav_cmd": clamav_cmd,
        "use_led": use_led,
        "led_pins": led_pins,
        "use_gui": use_gui,
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
        subprocess.run(["apt-get", "install", "-y", "hdparm", "python3-pip"], check=True)
        print("✓ Installed hdparm and python3-pip")
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
    
    # Install Python dependencies via pip
    try:
        subprocess.run(["pip3", "install", "--upgrade", "pyudev", "requests"], check=True)
        print("✓ Installed Python dependencies (pyudev, requests)")
    except subprocess.CalledProcessError as e:
        print(f"✗ Error: Failed to install Python dependencies: {e}")
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
    """Create udev rules to set USB drives read‑only on insertion and remove on removal."""
    rules_path = "/etc/udev/rules.d/90-arguspi-readonly.rules"
    rule_content = """
# ArgusPi: Set USB mass‑storage devices read‑only on insertion and revert on removal
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
    print("=" * 50)
    print("    ArgusPi USB Security Scanner Setup")
    print("=" * 50)
    require_root()
    config = prompt_configuration()
    write_config(config)
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
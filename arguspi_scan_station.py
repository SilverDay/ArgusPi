#!/usr/bin/env python3
"""
ArgusPi USB Scan Station – Automated USB malware scanning service for Raspberry Pi

ArgusPi is a comprehensive USB security scanning solution that monitors for new 
USB mass‑storage devices on a Raspberry Pi, mounts them read‑only with secure 
options, computes cryptographic hashes (SHA‑256) for every file on the device 
and, optionally, runs a local ClamAV scan before submitting suspicious hashes 
to VirusTotal for reputation analysis. After scanning, the device is automatically
unmounted and its read‑only status is cleared. Scan results are displayed on 
the console and logged locally. ArgusPi is designed to run as a daemon via a 
systemd service so that a USB checking station can be deployed with minimal 
user interaction.

Features
--------
* Automatic detection of USB mass‑storage insert/remove events using
  ``pyudev``.  Only partitions with a valid file system and coming from
  a USB bus are handled.
* Devices are put into a hardware read‑only state using ``hdparm``
  immediately when they are detected.  This minimises the risk of
  malware infection from autorun or other unwanted writes before the
  device is scanned.
* Filesystems are mounted read‑only with the ``ro``, ``noexec``,
  ``nosuid`` and ``nodev`` options to prevent execution of binaries
  from the USB stick and suppress privilege escalations.
* File hashes are calculated in a streaming fashion to handle large
  files efficiently.  SHA‑256 is the default algorithm because it 
  provides a strong balance between performance and resistance to collisions.
* Queries the VirusTotal v3 API for each unique hash and summarises
  detection counts from the analysis statistics.  Unknown files are
  reported separately.
* Results are printed to stdout so they can be shown on an attached
  display or captured by other processes.  Results are also logged
  to ``/var/log/arguspi.log`` for later review.
* Handles API rate limiting by waiting between requests.  The free
  VirusTotal tier allows 4 requests per minute; the default delay
  between requests is therefore 20 seconds but can be adjusted.

Configuration
-------------
ArgusPi expects a configuration file at ``/etc/arguspi/config.json``
containing at least the VirusTotal API key.  The provided installer
script creates this file and prompts the user for the key.  The
configuration file has the following structure::

    {
        "api_key": "YOUR_VIRUSTOTAL_API_KEY",
        "request_interval": 20,
        "mount_base": "/mnt/arguspi"
    }

If the file is missing or incomplete ArgusPi will exit with a
descriptive error message.

Logging
-------
Detailed information about each scan is appended to
``/var/log/arguspi.log``.  The log includes timestamps, device names,
hashes and VirusTotal results.  Rotating or monitoring this log is
recommended in production deployments.

Prerequisites
-------------
Install the following packages before running ArgusPi:

* Python3 and pip (usually already present on Raspberry Pi OS)
* ``pyudev`` – for monitoring USB events
* ``requests`` – for interacting with the VirusTotal API
* ``hdparm`` – to control device read‑only state

These can be installed via apt and pip::

    sudo apt update && sudo apt install -y hdparm python3-pip
    sudo pip3 install pyudev requests

Usage
-----
Once the configuration file is present and dependencies are installed,
start ArgusPi directly or via systemd.  When run in the foreground
it will output status messages to the console.  When run as a service
the messages can be viewed with ``journalctl -u arguspi``.

"""

import os
import sys
import json
import time
import signal
import subprocess
import hashlib
import socket
import logging
import logging.handlers
from datetime import datetime
from threading import Thread, Lock
from typing import Optional, Dict, Any
from urllib.parse import urlparse
import ipaddress

import pyudev  # type: ignore
import requests  # type: ignore
import tkinter as tk
from tkinter import ttk
from queue import Queue, Empty

try:
    from gpiozero import RGBLED
except ImportError:
    RGBLED = None  # type: ignore


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
            return False
        
        # Must have a hostname
        if not parsed.hostname:
            return False
        
        # Resolve hostname to IP to check for dangerous/reserved ranges
        try:
            ip_addr = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip_addr)
            
            # Only block truly dangerous addresses, not corporate networks
            if (ip_obj.is_loopback or       # 127.0.0.1, ::1 (localhost)
                ip_obj.is_link_local or     # 169.254.x.x (AWS/Azure metadata range)
                ip_obj.is_multicast or      # Multicast addresses
                ip_obj.is_unspecified):     # 0.0.0.0, ::
                return False
                
            # Additional check for specific dangerous IPs
            if str(ip_obj) in ['169.254.169.254', '127.0.0.1', '0.0.0.0', '::1']:
                return False
        except socket.gaierror:
            return False
        except Exception:
            return False
        
        # Additional checks for common SSRF bypass attempts and cloud metadata
        hostname_lower = parsed.hostname.lower()
        dangerous_hosts = [
            'localhost',
            'metadata.google.internal',  # Google Cloud metadata
            'instance-data',             # AWS instance metadata
            'metadata.azure.com',        # Azure metadata  
        ]
        
        # Block specific dangerous hostnames and patterns
        if (any(dangerous == hostname_lower for dangerous in dangerous_hosts) or
            any(dangerous in hostname_lower for dangerous in ['metadata', 'instance-data'])):
            return False
        
        return True
        
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Graphical user interface
# -----------------------------------------------------------------------------

class ArgusPiGUI:
    """
    ArgusPi full‑screen GUI for the USB scanning station.

    Displays the current scanning status with a coloured panel and
    descriptive text, and shows a log window of recent events.
    """

    def __init__(self) -> None:
        # Create root window
        self.root = tk.Tk()
        self.root.title("ArgusPi USB Security Scanner")
        # Use full screen on the Raspberry Pi Touch Display
        try:
            self.root.attributes("-fullscreen", True)
        except Exception:
            # Fallback for environments that do not support fullscreen
            self.root.geometry("800x480")
        self.root.configure(bg="black")
        
        # Create title banner
        self.title_frame = tk.Frame(self.root, bg="black")
        self.title_frame.pack(pady=10)
        
        # ArgusPi logo/title
        self.title_label = tk.Label(
            self.title_frame,
            text="ArgusPi",
            font=("Helvetica", 36, "bold"),
            fg="#00ff00",  # Bright green
            bg="black",
        )
        self.title_label.pack()
        
        # Subtitle
        self.subtitle_label = tk.Label(
            self.title_frame,
            text="USB Security Scanner",
            font=("Helvetica", 16),
            fg="white",
            bg="black",
        )
        self.subtitle_label.pack()
        
        # Define status variables
        self.status_var = tk.StringVar(value="Waiting for USB device…")
        
        # Create status panel
        self.status_frame = tk.Frame(self.root, width=400, height=120, bg="blue")
        self.status_frame.pack(pady=20)
        
        # Status label
        self.status_label = tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Helvetica", 20, "bold"),
            fg="white",
            bg="black",
        )
        self.status_label.pack(pady=10)
        
        # Log text area
        self.log_text = tk.Text(
            self.root,
            height=10,
            width=90,
            bg="black",
            fg="white",
            state="disabled",
            wrap="word",
            borderwidth=0,
            highlightthickness=0,
            font=("Courier", 9)
        )
        self.log_text.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Scrollbar for the log text
        self.scrollbar = tk.Scrollbar(self.log_text, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")

        # Mapping of statuses to colours and messages
        self._color_map = {
            "waiting": ("#0066cc", "Waiting for USB device…"),
            "scanning": ("#ffcc00", "Scanning USB device…"),
            "clean": ("#00cc00", "✓ Scan complete – No threats detected"),
            "infected": ("#cc0000", "⚠ THREATS DETECTED!"),
            "error": ("#cc0000", "✗ Error during scan"),
        }

    def set_status(self, status: str) -> None:
        """Update the status panel colour and label text."""
        colour, message = self._color_map.get(status, ("white", status))
        # Use after() to schedule GUI updates from other threads
        def update() -> None:
            self.status_frame.configure(bg=colour)
            self.status_var.set(message)
        try:
            self.root.after(0, update)
        except Exception:
            # root may not exist if GUI has been destroyed
            pass

    def append_log(self, line: str) -> None:
        """Append a line of text to the log area."""
        def update() -> None:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", line + "\n")
            # Auto‑scroll to the end
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        try:
            self.root.after(0, update)
        except Exception:
            pass

    def run(self) -> None:
        """Enter the Tk main loop."""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            # Gracefully exit on Ctrl‑C
            pass


class ArgusPiStation:
    """Main ArgusPi class implementing USB scanning functionality."""

    def __init__(self, config_path: str = "/etc/arguspi/config.json") -> None:
        self.config_path = config_path
        self.api_key: Optional[str] = None
        self.request_interval: int = 20  # seconds
        self.mount_base: str = "/mnt/arguspi"
        self.log_path: str = "/var/log/arguspi.log"
        # Local scanning with ClamAV
        self.use_clamav: bool = False
        self.clamav_cmd: str = "clamscan"
        # LED status indicator
        self.use_led: bool = False
        self.led_pins: Dict[str, int] = {"red": 17, "green": 27, "blue": 22}
        self.led: Optional[Any] = None
        # GUI configuration
        self.use_gui: bool = False
        self.gui: Optional['ArgusPiGUI'] = None
        # Station identification
        self.station_name: str = "arguspi-station"
        # SIEM integration
        self.siem_enabled: bool = False
        self.siem_type: str = "syslog"  # syslog, http, webhook
        self.siem_server: str = ""
        self.siem_port: int = 514
        self.siem_facility: str = "local0"
        self.siem_webhook_url: str = ""
        self.siem_headers: Dict[str, str] = {}
        self.siem_logger: Optional[logging.Logger] = None
        self._load_config()
        # Ensure mount base exists
        os.makedirs(self.mount_base, exist_ok=True)
        # Create log file if missing
        if not os.path.exists(self.log_path):
            open(self.log_path, "a").close()
        # Lock to serialise API requests
        self.api_lock = Lock()
        # Lock to synchronize LED operations
        self.led_lock = Lock()
        # Track active mounts for cleanup
        self.active_mounts = set()
        self.mount_lock = Lock()
        # Initialise LED after config loaded
        self._init_led()
        # Define colours for different statuses
        self.status_colors = {
            "waiting": (0.0, 0.0, 1.0),    # blue
            "scanning": (1.0, 1.0, 0.0),   # yellow
            "clean": (0.0, 1.0, 0.0),      # green
            "infected": (1.0, 0.0, 0.0),   # red
        }
        # Initialise GUI if enabled
        if self.use_gui:
            try:
                self.gui = ArgusPiGUI()
            except Exception as e:
                self.log(f"Failed to initialise ArgusPi GUI: {e}. Running headless.", "WARN")
                self.use_gui = False

    def _load_config(self) -> None:
        """Load configuration from JSON file.  Raise exception if missing."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(
                f"ArgusPi configuration file {self.config_path} not found. "
                "Run the setup script to create it."
            )
        with open(self.config_path, "r") as f:
            data = json.load(f)
        
        # VirusTotal API key is now optional for offline/air-gapped environments
        api_key = data.get("api_key", "").strip()
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = None
            self.log("VirusTotal API key not configured - running in offline mode", "INFO")
        
        self.request_interval = int(data.get("request_interval", 20))
        self.mount_base = data.get("mount_base", "/mnt/arguspi")
        # load optional clamav configuration
        self.use_clamav = bool(data.get("use_clamav", False))
        self.clamav_cmd = data.get("clamav_cmd", "clamscan")
        # LED configuration
        self.use_led = bool(data.get("use_led", False))
        pins = data.get("led_pins", None)
        if pins and all(k in pins for k in ("red", "green", "blue")):
            self.led_pins = {"red": int(pins["red"]), "green": int(pins["green"]), "blue": int(pins["blue"])}
        # GUI configuration
        self.use_gui = bool(data.get("use_gui", False))
        # Station identification
        self.station_name = data.get("station_name", "arguspi-station")
        # SIEM configuration
        self.siem_enabled = bool(data.get("siem_enabled", False))
        if self.siem_enabled:
            self.siem_type = data.get("siem_type", "syslog").lower()
            self.siem_server = data.get("siem_server", "")
            self.siem_port = int(data.get("siem_port", 514))
            self.siem_facility = data.get("siem_facility", "local0")
            
            # Validate webhook URL for SSRF protection
            webhook_url = data.get("siem_webhook_url", "")
            if webhook_url and not validate_webhook_url(webhook_url):
                self.log("WARNING: Invalid or potentially dangerous webhook URL detected. SIEM webhook disabled for security.", "WARN")
                webhook_url = ""
            self.siem_webhook_url = webhook_url
            
            self.siem_headers = data.get("siem_headers", {})
            self._init_siem_logger()

    def _init_siem_logger(self) -> None:
        """Initialize SIEM logger based on configuration."""
        if not self.siem_enabled:
            return
            
        try:
            self.siem_logger = logging.getLogger('arguspi_siem')
            self.siem_logger.setLevel(logging.INFO)
            
            # Remove existing handlers
            self.siem_logger.handlers.clear()
            
            if self.siem_type == "syslog":
                # Syslog handler for SIEM integration
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
                facility = facility_map.get(self.siem_facility, logging.handlers.SysLogHandler.LOG_LOCAL0)
                
                if self.siem_server:
                    handler = logging.handlers.SysLogHandler(
                        address=(self.siem_server, self.siem_port),
                        facility=facility
                    )
                else:
                    handler = logging.handlers.SysLogHandler(facility=facility)
                
                # RFC 5424 format for better SIEM parsing
                formatter = logging.Formatter(
                    'arguspi[%(process)d]: %(name)s %(levelname)s %(message)s'
                )
                handler.setFormatter(formatter)
                self.siem_logger.addHandler(handler)
                self.log(f"SIEM syslog integration enabled: {self.siem_server or 'local'}:{self.siem_port}", "INFO")
            
            elif self.siem_type in ["http", "webhook"]:
                # HTTP/Webhook integration will be handled in send_siem_event method
                self.log(f"SIEM {self.siem_type} integration enabled: {self.siem_webhook_url}", "INFO")
                
        except Exception as e:
            self.log(f"Failed to initialize SIEM integration: {e}", "ERROR")
            self.siem_enabled = False

    def log(self, message: str, level: str = "INFO") -> None:
        """Append a timestamped message to the log file and stdout."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{timestamp} [ArgusPi-{level}] - {message}"
        print(line)
        try:
            with open(self.log_path, "a") as logf:
                logf.write(line + "\n")
        except PermissionError:
            # If logging fails, still continue scanning
            print(f"Warning: Cannot write to ArgusPi log file {self.log_path}")
        except Exception as e:
            print(f"Warning: ArgusPi logging error: {e}")
        # Also append to GUI if available
        if self.gui:
            self.gui.append_log(f"[{level}] {message}")

    def send_siem_event(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """Send structured event data to SIEM platform."""
        if not self.siem_enabled:
            return
            
        try:
            # Create standardized SIEM event
            siem_event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "source": "arguspi",
                "station_name": self.station_name,
                "hostname": socket.gethostname(),
                "event_type": event_type,
                "severity": self._get_event_severity(event_type, event_data),
                "data": event_data
            }
            
            if self.siem_type == "syslog" and self.siem_logger:
                # Send as structured syslog message with station name
                message = f"station_name={self.station_name} event_type={event_type} " + " ".join([
                    f"{k}={json.dumps(v) if isinstance(v, (dict, list)) else v}" 
                    for k, v in event_data.items()
                ])
                
                severity = siem_event["severity"]
                if severity == "high":
                    self.siem_logger.error(message)
                elif severity == "medium":
                    self.siem_logger.warning(message)
                else:
                    self.siem_logger.info(message)
                    
            elif self.siem_type in ["http", "webhook"] and self.siem_webhook_url:
                # Send as HTTP POST with JSON payload
                headers = {"Content-Type": "application/json"}
                headers.update(self.siem_headers)
                
                response = requests.post(
                    self.siem_webhook_url,
                    json=siem_event,
                    headers=headers,
                    timeout=10
                )
                response.raise_for_status()
                
        except Exception as e:
            self.log(f"Failed to send SIEM event: {e}", "WARN")
            
    def _get_event_severity(self, event_type: str, event_data: Dict[str, Any]) -> str:
        """Determine event severity for SIEM classification."""
        if event_type == "threat_detected":
            return "high"
        elif event_type == "scan_error":
            return "medium"
        elif event_type in ["scan_started", "scan_completed"]:
            if event_data.get("infected_files", 0) > 0:
                return "high"
            elif event_data.get("errors", 0) > 0:
                return "medium"
            else:
                return "low"
        else:
            return "low"

    # --------------------------------------------------------------------------
    # LED handling
    # --------------------------------------------------------------------------
    def _init_led(self) -> None:
        """Initialise the RGB LED if configured and available."""
        if not self.use_led or RGBLED is None:
            return
        try:
            # active_high=True for common cathode LEDs (driving high turns LED on)
            self.led = RGBLED(
                red=self.led_pins["red"],
                green=self.led_pins["green"],
                blue=self.led_pins["blue"],
                active_high=True,
                pwm=True,
            )
            self.log(f"ArgusPi RGB LED initialized on pins R:{self.led_pins['red']} G:{self.led_pins['green']} B:{self.led_pins['blue']}")
        except Exception as e:
            # If LED fails to initialise, disable LED usage
            self.log(f"Failed to initialise ArgusPi RGB LED: {e}. Disabling LED indicator.", "WARN")
            self.use_led = False
            self.led = None

    def set_led_color(self, r: float, g: float, b: float) -> None:
        """Set LED to a specific RGB colour."""
        with self.led_lock:
            if self.led:
                # Stop any blinking
                try:
                    self.led.off()
                except Exception:
                    pass
                try:
                    self.led.color = (r, g, b)
                except Exception:
                    pass

    def blink_error(self) -> None:
        """Blink the LED red to indicate an error."""
        with self.led_lock:
            if self.led:
                # blink on/off at 0.5 second intervals; run in background
                try:
                    self.led.blink(on_time=0.5, off_time=0.5)
                except Exception:
                    pass

    def update_status(self, status: str) -> None:
        """Update the LED and GUI based on the named status."""
        # Update LED if configured
        if self.use_led:
            if status == "error":
                self.blink_error()
            else:
                colour = self.status_colors.get(status)
                if colour:
                    self.set_led_color(*colour)
        # Always update GUI if present
        if self.gui:
            self.gui.set_status(status)

    @staticmethod
    def compute_hash(file_path: str) -> str:
        """Compute SHA‑256 hash of a file in a memory‑efficient way.
        
        Raises:
            FileNotFoundError: If file doesn't exist (device removed)
            PermissionError: If file access denied
            OSError: If I/O error occurs (device disconnected)
        """
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
        except (FileNotFoundError, PermissionError, OSError):
            # Re-raise these specific exceptions for caller to handle
            raise
        return sha256.hexdigest()

    def query_virustotal(self, file_hash: str) -> Optional[Dict[str, int]]:
        """Query VirusTotal for a file hash.

        Returns a dictionary with detection counts or None on error.
        Implements simple rate limiting to respect the free API quota by
        sleeping between consecutive requests while holding a lock.
        
        Returns None immediately if no API key is configured (offline mode).
        """
        if self.api_key is None:
            return None
            
        with self.api_lock:
            headers = {"x-apikey": self.api_key}
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            try:
                try:
                    response = requests.get(url, headers=headers, timeout=30)
                except Exception as exc:
                    self.log(f"Error contacting VirusTotal: {exc}", "ERROR")
                    return None
                if response.status_code == 200:
                    try:
                        data = response.json()
                        stats = data["data"]["attributes"]["last_analysis_stats"]
                        return {
                            "malicious": int(stats.get("malicious", 0)),
                            "suspicious": int(stats.get("suspicious", 0)),
                            "undetected": int(stats.get("undetected", 0)),
                            "timeout": int(stats.get("timeout", 0)),
                        }
                    except (ValueError, KeyError) as parse_err:
                        self.log(f"Error parsing VirusTotal response: {parse_err}", "ERROR")
                        return None
                elif response.status_code == 404:
                    # Unknown file
                    return {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 0,
                        "timeout": 0,
                    }
                else:
                    self.log(
                        f"VirusTotal API returned status {response.status_code}: {response.text}", "WARN"
                    )
                    return None
            finally:
                # Ensure a delay between API requests to respect rate limits
                time.sleep(self.request_interval)

    def scan_path(self, mount_point: str) -> None:
        """Traverse a mounted filesystem, optionally run ClamAV, hash files and query VirusTotal.

        If ``use_clamav`` is enabled in the configuration, files will first
        be scanned locally with ClamAV.  Only files reported as infected or
        if ClamAV returns an error will be submitted to VirusTotal.  This
        behaviour reduces the number of API calls and improves overall
        performance while still providing an additional detection layer.
        """
        infected_found = False
        error_occurred = False
        total_files = 0
        infected_files = 0
        
        # Send SIEM event for scan start
        self.send_siem_event("scan_started", {
            "mount_point": mount_point,
            "device": os.path.basename(mount_point),
            "scan_mode": "clamav+virustotal" if self.use_clamav else "virustotal_only" if self.api_key else "local_only"
        })
        
        try:
            for root, dirs, files in os.walk(mount_point):
                for name in files:
                    file_path = os.path.join(root, name)
                    total_files += 1
                    
                    # Check if mount point still exists (device removed)
                    if not os.path.exists(mount_point):
                        self.log("USB device was removed during scan. Aborting scan.", "WARN")
                        return None
                    
                    # Run a local ClamAV scan first if enabled
                    local_scan_infected = False
                    local_scan_error = False
                    if self.use_clamav:
                        try:
                            result = subprocess.run(
                                [self.clamav_cmd, "--infected", "--no-summary", file_path],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                            )
                            if result.returncode == 1:
                                local_scan_infected = True
                            elif result.returncode == 2:
                                local_scan_error = True
                        except FileNotFoundError:
                            self.log("ClamAV executable not found; skipping local scan.", "WARN")
                            self.use_clamav = False
                        except Exception as e:
                            self.log(f"ClamAV scan failed for {file_path}: {e}", "WARN")
                            local_scan_error = True
                    
                    # Compute hash for logging and possible VT lookup
                    try:
                        file_hash = self.compute_hash(file_path)
                    except (FileNotFoundError, PermissionError, OSError) as e:
                        self.log(f"Failed to access file {file_path} (device may have been removed): {e}", "WARN")
                        error_occurred = True
                        continue
                    except Exception as e:
                        self.log(f"Failed to compute hash for {file_path}: {e}", "ERROR")
                        error_occurred = True
                        continue
                    
                    # Decide whether to query VirusTotal
                vt_result = None
                status = "clean"
                if self.use_clamav and not local_scan_infected and not local_scan_error:
                    # Local scan clean; skip VT
                    status = "clean"
                elif self.api_key is None:
                    # Offline mode - no VirusTotal available
                    if local_scan_infected:
                        status = "infected"
                    elif local_scan_error:
                        status = "error" 
                    else:
                        status = "clean"
                else:
                    # Online mode - query VirusTotal
                    vt_result = self.query_virustotal(file_hash)
                    if vt_result is None:
                        status = "error"
                        error_occurred = True
                    elif vt_result["malicious"] > 0 or vt_result["suspicious"] > 0:
                        status = "infected"
                        infected_found = True
                        infected_files += 1
                        # Send SIEM threat detection event
                        self.send_siem_event("threat_detected", {
                            "file_path": file_path,
                            "file_name": name,
                            "file_hash": file_hash,
                            "device": os.path.basename(mount_point),
                            "detection_method": "virustotal",
                            "malicious_count": vt_result["malicious"],
                            "suspicious_count": vt_result["suspicious"],
                            "total_engines": vt_result.get("total", 0)
                        })
                    else:
                        status = "clean"
                # Update infected flag from local scan
                if local_scan_infected:
                    infected_found = True
                    infected_files += 1
                    status = "infected"
                    # Send SIEM threat detection event for ClamAV detection
                    self.send_siem_event("threat_detected", {
                        "file_path": file_path,
                        "file_name": name,
                        "file_hash": file_hash,
                        "device": os.path.basename(mount_point),
                        "detection_method": "clamav"
                    })
                if local_scan_error:
                    error_occurred = True
                    status = "error"
                # Combine details for logging
                details: Dict[str, object] = {}
                if self.use_clamav:
                    details["local_infected"] = local_scan_infected
                    details["local_error"] = local_scan_error
                if vt_result is not None:
                    details["vt"] = vt_result
                # Log the outcome
                self.log(
                    f"{status.upper()} | {file_hash} | {name} | details: {details}"
                )
        
        except (OSError, FileNotFoundError, PermissionError) as e:
            self.log(f"USB device access failed during scan (device likely removed): {e}", "WARN")
            return None
        except Exception as e:
            self.log(f"Unexpected error during filesystem scan: {e}", "ERROR")
            error_occurred = True
        
        # Send SIEM event for scan completion
        scan_result = "error" if error_occurred else "infected" if infected_found else "clean"
        self.send_siem_event("scan_completed", {
            "mount_point": mount_point,
            "device": os.path.basename(mount_point),
            "result": scan_result,
            "total_files": total_files,
            "infected_files": infected_files,
            "errors": 1 if error_occurred else 0,
            "scan_mode": "clamav+virustotal" if self.use_clamav else "virustotal_only" if self.api_key else "local_only"
        })
        
        # Return status based on what was found during scanning
        if error_occurred:
            return None  # Indicates an error occurred
        return infected_found  # True if any infected files found, False if clean

    def mount_device(self, device_node: str) -> Optional[str]:
        """Mount the given block device read‑only with secure options.

        Returns the mount path or None if mounting failed.
        """
        device_name = os.path.basename(device_node)
        mount_point = os.path.join(self.mount_base, device_name)
        os.makedirs(mount_point, exist_ok=True)
        # Put device into read‑only state (ignore errors)
        subprocess.run(["/sbin/hdparm", "-r1", device_node], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Try to mount with safe options
        try:
            subprocess.run(
                [
                    "/bin/mount",
                    "-o",
                    "ro,noexec,nosuid,nodev,sync",  # sync to avoid write caching
                    device_node,
                    mount_point,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Track this mount for cleanup
            with self.mount_lock:
                self.active_mounts.add((device_node, mount_point))
            return mount_point
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to mount {device_node}: {e}", "ERROR")
            # Reset read‑only flag on failure
            subprocess.run(["/sbin/hdparm", "-r0", device_node], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return None

    def unmount_device(self, device_node: str, mount_point: str) -> None:
        """Unmount and clean up a device."""
        try:
            subprocess.run(["/bin/umount", mount_point], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            # Reset read‑only flag so the user can use the drive again
            subprocess.run(["/sbin/hdparm", "-r0", device_node], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Remove from active mounts tracking
            with self.mount_lock:
                self.active_mounts.discard((device_node, mount_point))
            # Remove mount directory if empty
            try:
                os.rmdir(mount_point)
            except OSError:
                pass

    def cleanup_all_mounts(self) -> None:
        """Clean up all active mounts on shutdown."""
        with self.mount_lock:
            mounts_to_cleanup = list(self.active_mounts)
        
        for device_node, mount_point in mounts_to_cleanup:
            self.log(f"Cleaning up mount: {mount_point}", "INFO")
            self.unmount_device(device_node, mount_point)

    def handle_device(self, device) -> None:
        """Perform scanning for a newly added USB device."""
        device_node = device.device_node
        self.log(f"ArgusPi detected USB device {device_node}. Preparing to scan...")
        mount_point = self.mount_device(device_node)
        if mount_point:
            # Set LED to scanning state
            self.update_status("scanning")
            try:
                self.log(f"Mounted {device_node} at {mount_point}. Beginning ArgusPi scan.")
                result = self.scan_path(mount_point)
                # Determine LED outcome based on result
                if result is None:
                    self.update_status("error")
                elif result is True:
                    self.update_status("infected")
                else:
                    self.update_status("clean")
            finally:
                self.unmount_device(device_node, mount_point)
                self.log(f"ArgusPi completed scan of {device_node} and unmounted.")
                # Return to waiting state
                self.update_status("waiting")
        else:
            self.log(f"ArgusPi skipping scan for {device_node} due to mount failure.")
            self.update_status("error")

    def monitor_devices(self) -> None:
        """Monitor for USB block devices and trigger scanning on insert."""
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem="block", device_type="partition")
        self.log("ArgusPi USB scan service started. Waiting for devices...")
        # Indicate waiting status on LED
        self.update_status("waiting")
        for device in iter(monitor.poll, None):
            try:
                # Only handle 'add' events; ignore removals
                if device.action != "add":
                    continue
                # Only handle devices from the USB bus
                if device.get("ID_BUS") != "usb":
                    continue
                # Skip devices with no filesystem type (e.g. raw partitions)
                if "ID_FS_TYPE" not in device:
                    continue
                # Handle scanning in a new thread to avoid blocking further events
                t = Thread(target=self.handle_device, args=(device,), daemon=True)
                t.start()
            except Exception as e:
                self.log(f"Exception while processing device event: {e}", "ERROR")

    def run(self) -> None:
        """Run the monitoring loop and gracefully handle termination signals."""
        def sigterm_handler(signum, frame):
            self.log("ArgusPi termination signal received. Cleaning up...")
            # Clean up any active mounts
            self.cleanup_all_mounts()
            # If GUI running, quit main loop
            if self.gui:
                try:
                    self.gui.root.quit()
                except Exception:
                    pass
            self.log("ArgusPi cleanup complete. Exiting...")
            sys.exit(0)

        signal.signal(signal.SIGTERM, sigterm_handler)
        signal.signal(signal.SIGINT, sigterm_handler)
        if self.use_gui and self.gui:
            # Start monitor in a background thread
            t = Thread(target=self.monitor_devices, daemon=True)
            t.start()
            # Start GUI loop
            self.gui.run()
        else:
            # Run monitoring loop in foreground (headless)
            self.monitor_devices()


def main() -> None:
    try:
        station = ArgusPiStation()
    except Exception as err:
        print(f"ArgusPi Error: {err}")
        sys.exit(1)
    station.run()


if __name__ == "__main__":
    main()
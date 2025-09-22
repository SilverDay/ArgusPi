#!/usr/bin/env python3
"""
ArgusPi USB Scan Station - Automated USB malware scanning service for Raspberry Pi

ArgusPi is a comprehensive USB security scanning solution that monitors for new
USB mass-storage devices on a Raspberry Pi, mounts them read-only with secure
options, computes cryptographic hashes (SHA-256) for every file on the device
and, optionally, runs a local ClamAV scan before submitting suspicious hashes
to VirusTotal for reputation analysis. After scanning, the device is automatically
unmounted and its read-only status is cleared. Scan results are displayed on
the console and logged locally. ArgusPi is designed to run as a daemon via a
systemd service so that a USB checking station can be deployed with minimal
user interaction.

Features
--------
* Automatic detection of USB mass-storage insert/remove events using
  ``pyudev``.  Only partitions with a valid file system and coming from
  a USB bus are handled.
* Devices are put into a hardware read-only state using ``hdparm``
  immediately when they are detected.  This minimises the risk of
  malware infection from autorun or other unwanted writes before the
  device is scanned.
* Filesystems are mounted read-only with the ``ro``, ``noexec``,
  ``nosuid`` and ``nodev`` options to prevent execution of binaries
  from the USB stick and suppress privilege escalations.
* File hashes are calculated in a streaming fashion to handle large
  files efficiently.  SHA-256 is the default algorithm because it
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
* ``pyudev`` - for monitoring USB events
* ``requests`` - for interacting with the VirusTotal API
* ``hdparm`` - to control device read-only state

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
import time
import tkinter as tk
import tkinter.ttk as ttk
import random
from datetime import datetime
from threading import Thread, Lock
from typing import Optional, Dict, Any
from urllib.parse import urlparse
import ipaddress

import pyudev  # type: ignore
import requests  # type: ignore

try:
    from gpiozero import RGBLED  # type: ignore
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
    ArgusPi full-screen GUI for the USB scanning station.

    Displays the current scanning status with a coloured panel and
    descriptive text, and shows a log window of recent events.
    """

    def __init__(self, simple_mode: bool = False, display_rotation: int = 0) -> None:
        # Store display mode and rotation
        self.simple_mode = simple_mode
        self.display_rotation = display_rotation
        
        # Initialize scan progress tracking
        self.scan_start_time = None
        self.scan_progress = {"current": 0, "total": 0}
        self.current_action = "Waiting for USB device…"
        
        # Create root window
        self.root = tk.Tk()
        self.root.title("ArgusPi USB Security Scanner")
        
        # Apply rotation logic - this affects the window geometry
        self._apply_display_rotation()
        
        # Handle DPI scaling issues
        self._configure_dpi_scaling()
        
        # Configure fullscreen display for kiosk mode
        try:
            # Simple one-time fullscreen setup - don't fight the window manager
            self.root.update_idletasks()
            
            # Set basic fullscreen without aggressive geometry enforcement
            self.root.attributes("-fullscreen", True)
            self.root.configure(bg="black")
            
            # Force focus to prevent dialogs from stealing focus
            self.root.focus_force()
            self.root.grab_set()  # Grab all events to prevent other windows from appearing
            
            print("✓ GUI running in fullscreen mode with focus lock")
            
        except tk.TclError as e:
            print(f"⚠ Fullscreen mode failed ({e}), using maximized window")
            # Fallback to maximized window
            try:
                self.root.state('zoomed')  # Windows maximize
                self.root.focus_force()
            except tk.TclError:
                try:
                    self.root.attributes('-zoomed', True)  # Linux maximize
                    self.root.focus_force()
                except tk.TclError:
                    # Final fallback - just use whatever size we get
                    print("⚠ Using default window size")
        except Exception as e:
            print(f"⚠ Display configuration failed ({e}), using default size")

        # Configure root window
        self.root.configure(bg="black")

        # Screensaver configuration
        self.screensaver_timeout = 300000  # 5 minutes in milliseconds
        self.screensaver_active = False
        self.last_activity = 0
        self.screensaver_elements = []

        # Bind mouse and key events to detect activity
        self.root.bind('<Motion>', self._on_activity)
        self.root.bind('<Button>', self._on_activity)
        self.root.bind('<Key>', self._on_activity)
        self.root.focus_set()  # Enable key events
        
        # DISABLED: Aggressive window resize monitoring that causes infinite loops
        # self.root.bind('<Configure>', self._on_window_configure)

        # Create title banner
        self.title_frame = tk.Frame(self.root, bg="black")
        self.title_frame.pack(pady=30)  # Increased padding

        # ArgusPi logo/title - Much larger for fullscreen
        self.title_label = tk.Label(
            self.title_frame,
            text="ArgusPi",
            font=("Helvetica", 72, "bold"),  # Doubled from 36 to 72
            fg="#00ff00",  # Bright green
            bg="black",
        )
        self.title_label.pack()

        # Subtitle - Larger for fullscreen
        self.subtitle_label = tk.Label(
            self.title_frame,
            text="USB Security Scanner",
            font=("Helvetica", 32),  # Doubled from 16 to 32
            fg="white",
            bg="black",
        )
        self.subtitle_label.pack()

        # Define status variables
        self.status_var = tk.StringVar(value="Waiting for USB device…")
        self.current_status_key = "waiting"  # Track current status for screensaver restoration

        # Define color mapping BEFORE using it (FIXED: was causing AttributeError)
        self._color_map = {
            "waiting": ("#0066cc", "Waiting for USB device…"),
            "scanning": ("#ffcc00", "Scanning USB device…"),
            "clean": ("#00cc00", "✓ Scan complete - No threats detected"),
            "infected": ("#cc0000", "⚠ THREATS DETECTED!"),
            "error": ("#cc0000", "✗ Error during scan"),
            # Persistent result statuses (shown until USB device is removed)
            "scan_clean": ("#00cc00", "✅ SUCCESS: USB device is clean - Safe to remove"),
            "scan_infected": ("#cc0000", "🦠 INFECTED: Malware detected - Remove immediately!"),
            "scan_error": ("#cc6600", "⚠️ ERROR: Scan failed - Check device and try again"),
        }

        # Create status panel - use proper color mapping instead of hardcoded blue
        initial_color = self._get_status_color("waiting")
        # Get screen dimensions for responsive sizing
        screen_width, screen_height = self._get_screen_dimensions()
        status_width = max(600, int(screen_width * 0.6))  # Increased to 60% of screen width, minimum 600px
        status_height = max(180, int(screen_height * 0.15))  # Scale height with screen size too
        self.status_frame = tk.Frame(self.root, width=status_width, height=status_height, bg=initial_color)
        self.status_frame.pack(pady=40)  # Increased padding

        # Status label - Much larger font
        self.status_label = tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Helvetica", 40, "bold"),  # Doubled from 20 to 40
            fg="white",
            bg="black",
        )
        self.status_label.pack(pady=10)

        # Create simple mode or detailed mode display
        if self.simple_mode:
            self._create_simple_mode_display()
        else:
            self._create_detailed_mode_display()

    def _get_screen_dimensions(self) -> tuple[int, int]:
        """Get accurate screen dimensions using multiple detection methods with timeout protection."""
        import time
        start_time = time.time()
        timeout_seconds = 10  # Maximum time to spend on screen detection
        
        try:
            # Method 1: Try system commands first (most accurate after rpi-update) - but with timeout
            if time.time() - start_time < timeout_seconds:
                screen_width, screen_height = self._get_system_screen_dimensions()
                if screen_width and screen_height:
                    return screen_width, screen_height
            else:
                print("⚠ Screen detection timed out, using fallback")
            
            # Method 2: Force Tkinter to update and get dimensions (but with timeout protection)
            if time.time() - start_time < timeout_seconds:
                try:
                    self.root.update_idletasks()
                    width = self.root.winfo_screenwidth()
                    height = self.root.winfo_screenheight()
                    if width > 0 and height > 0:
                        print(f"📱 Tkinter detected: {width}x{height}")
                        return width, height
                except Exception as e:
                    print(f"⚠ Tkinter dimension detection failed: {e}")
            
            # Method 3: Common Raspberry Pi display resolutions as fallbacks
            print("⚠ Using fallback resolution detection")
            fallback_resolutions = [
                (1280, 720),   # 7" DSI display rotated
                (720, 1280),   # 7" DSI display normal
                (1024, 600),   # 7" HDMI displays
                (800, 480),    # 5" displays
                (1920, 1080),  # Full HD
            ]
            return fallback_resolutions[0]  # Default to most common rotated resolution
            
        except Exception as e:
            print(f"⚠ Screen dimension detection completely failed: {e}")
            return (1280, 720)  # Safe fallback

    def _get_system_screen_dimensions(self) -> tuple[int, int]:
        """Get screen dimensions using system commands with robust timeout handling."""
        try:
            import subprocess
            
            # Try wlr-randr first (Wayland) with strict timeout
            try:
                result = subprocess.run(["wlr-randr"], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if 'current' in line and 'x' in line:
                            # Parse: "1280x720 @ 60.000000 Hz" 
                            try:
                                resolution = line.split()[0]
                                if 'x' in resolution:
                                    width, height = map(int, resolution.split('x'))
                                    print(f"🖥️ wlr-randr detected: {width}x{height}")
                                    return width, height
                            except (ValueError, IndexError):
                                continue
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
                print("⚠ wlr-randr timed out or failed")
            
            # Try xrandr (X11) with strict timeout
            try:
                result = subprocess.run(["xrandr"], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '*' in line and 'x' in line:  # Current resolution marked with *
                            try:
                                parts = line.strip().split()
                                resolution = parts[0]
                                if 'x' in resolution:
                                    width, height = map(int, resolution.split('x'))
                                    print(f"🖥️ xrandr detected: {width}x{height}")
                                    return width, height
                            except (ValueError, IndexError):
                                continue
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
                print("⚠ xrandr timed out or failed")
            
            # Try fbset (framebuffer) with strict timeout
            try:
                result = subprocess.run(["fbset"], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'geometry' in line:
                            try:
                                parts = line.strip().split()
                                width = int(parts[1])
                                height = int(parts[2])
                                print(f"🖥️ fbset detected: {width}x{height}")
                                return width, height
                            except (ValueError, IndexError):
                                continue
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
                print("⚠ fbset timed out or failed")
            
        except Exception as e:
            print(f"⚠ System screen detection failed: {e}")
        
        print("⚠ All system screen detection methods failed, using fallback")
        return 0, 0  # Indicate failure

    def _configure_dpi_scaling(self) -> None:
        """Configure DPI scaling to prevent half-screen issues."""
        try:
            # Force Tkinter to use system DPI
            self.root.tk.call('tk', 'scaling', 1.0)
            
            # Try to disable DPI awareness that might cause scaling issues
            try:
                import ctypes
                # On Linux with X11, try to set DPI explicitly
                import subprocess
                try:
                    result = subprocess.run(["xrdb", "-query"], capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and "Xft.dpi" not in result.stdout:
                        # Set DPI to standard 96 if not set
                        subprocess.run(["xrdb", "-merge"], input="Xft.dpi: 96\n", 
                                     text=True, timeout=3)
                        print("✓ Set X11 DPI to standard 96")
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                    print(f"⚠ X11 DPI configuration skipped: {e}")
            except Exception:
                pass
            
            print("✓ DPI scaling configured")
        except Exception as e:
            print(f"⚠ DPI scaling configuration failed: {e}")

    def _disable_window_manager_interference(self) -> None:
        """Disable window manager features that might interfere with fullscreen."""
        try:
            # Set window properties to prevent window manager interference
            self.root.wm_attributes("-type", "splash")  # Splash windows are often unmanaged
            
            # Try to set window hints for different window managers
            try:
                # KDE/LXDE hints
                self.root.wm_attributes("-topmost", True)
            except tk.TclError:
                pass
            
            try:
                # Set WM class for window manager recognition
                self.root.wm_class("ArgusPi", "Kiosk")
            except tk.TclError:
                pass
                
            # Attempt to disable window manager decorations more aggressively
            try:
                import subprocess
                
                # Try to disable desktop environment window management for this window
                # Get window ID after it's created
                self.root.update_idletasks()
                
                # For labwc/Wayland - try to set window properties
                subprocess.run([
                    "swaymsg", "[class=ArgusPi]", "floating", "enable"
                ], capture_output=True, timeout=2)
                
                subprocess.run([
                    "swaymsg", "[class=ArgusPi]", "fullscreen", "enable"
                ], capture_output=True, timeout=2)
                
            except Exception:
                pass  # Window manager commands might not be available
                
            print("✓ Window manager interference mitigation applied")
            
        except Exception as e:
            print(f"⚠ Window manager configuration failed: {e}")

    def _apply_display_rotation(self) -> None:
        """Apply display rotation with comprehensive system integration."""        
        if self.display_rotation == 0:
            print("✓ Display rotation: 0° (normal)")
            return
            
        rotation_names = {0: "0° (normal)", 1: "90° clockwise", 2: "180°", 3: "270° clockwise"}
        print(f"🔄 Applying display rotation: {rotation_names.get(self.display_rotation, 'unknown')}")
        
        # Try multiple rotation methods in order of effectiveness
        methods_tried = []
        
        # Method 1: wlr-randr (Wayland - modern Raspberry Pi OS)
        if self._try_wlr_randr_rotation():
            methods_tried.append("wlr-randr ✓")
        else:
            methods_tried.append("wlr-randr ✗")
            
        # Method 2: xrandr (X11 - older systems)
        if self._try_xrandr_rotation():
            methods_tried.append("xrandr ✓")
        else:
            methods_tried.append("xrandr ✗")
            
        # Method 3: Direct framebuffer rotation (if available)
        if self._try_framebuffer_rotation():
            methods_tried.append("framebuffer ✓")
        else:
            methods_tried.append("framebuffer ✗")
        
        print(f"🔧 Rotation methods tried: {', '.join(methods_tried)}")
        
        # Configure touch input transformation
        self._configure_touch_rotation()
        
        # Disable desktop auto-mount dialogs for kiosk mode
        self._disable_automount_dialogs()
        
        # Provide manual configuration guidance
        self._show_manual_rotation_config()

    def _try_wlr_randr_rotation(self) -> bool:
        """Try rotation using wlr-randr (Wayland/labwc on modern Raspberry Pi OS)."""
        try:
            import subprocess
            
            # Check if wlr-randr is available
            result = subprocess.run(["which", "wlr-randr"], capture_output=True, text=True, timeout=3)
            if result.returncode != 0:
                return False
                
            # Map rotation values to wlr-randr parameters  
            wlr_rotations = {1: "90", 2: "180", 3: "270"}
            wlr_rotation = wlr_rotations.get(self.display_rotation)
            
            if wlr_rotation:
                # Get available outputs
                result = subprocess.run(["wlr-randr"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    output_lines = result.stdout.strip().split('\n')
                    outputs = [line.split()[0] for line in output_lines if line and not line.startswith(' ')]
                    
                    for output in outputs:
                        if output:  # Skip empty outputs
                            result = subprocess.run([
                                "wlr-randr", "--output", output, "--transform", wlr_rotation
                            ], capture_output=True, text=True, timeout=5)
                            
                            if result.returncode == 0:
                                print(f"✓ Applied Wayland rotation via wlr-randr on {output}: {wlr_rotation}°")
                                return True
            
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return False

    def _try_xrandr_rotation(self) -> bool:
        """Attempt to rotate display using xrandr command (X11)."""
        try:
            import subprocess
            
            # Map rotation values to xrandr parameters
            xrandr_rotations = {1: "left", 2: "inverted", 3: "right"}
            xrandr_rotation = xrandr_rotations.get(self.display_rotation)
            
            if xrandr_rotation:
                # Try common display output names for Raspberry Pi
                display_names = ["DSI-1", "HDMI-1", "HDMI-2", "DPI-1", "HDMI-A-1", "HDMI-A-2"]
                
                for display_name in display_names:
                    result = subprocess.run([
                        "xrandr", "--output", display_name, "--rotate", xrandr_rotation
                    ], capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        print(f"✓ Applied X11 rotation via xrandr on {display_name}: {xrandr_rotation}")
                        return True
            
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return False

    def _try_framebuffer_rotation(self) -> bool:
        """Try to apply rotation via framebuffer console."""
        try:
            import subprocess
            
            # Try to rotate framebuffer console (affects console before X/Wayland starts)
            fb_rotation = self.display_rotation
            result = subprocess.run([
                "sudo", "bash", "-c", f"echo {fb_rotation} > /sys/class/graphics/fbcon/rotate_all"
            ], capture_output=True, text=True, timeout=3)
            
            if result.returncode == 0:
                print(f"✓ Applied framebuffer console rotation: {fb_rotation}")
                return True
            
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return False

    def _configure_touch_rotation(self) -> None:
        """Configure touch input coordinate transformation for rotation."""
        if self.display_rotation == 0:
            return
            
        try:
            import subprocess
            
            # Create transformation matrix for libinput
            # Rotation matrices for coordinate transformation
            transforms = {
                1: "0 -1 1 1 0 0 0 0 1",    # 90° clockwise
                2: "-1 0 1 0 -1 1 0 0 1",   # 180°
                3: "0 1 0 -1 0 1 0 0 1"     # 270° clockwise (90° counter-clockwise)
            }
            
            transform_matrix = transforms.get(self.display_rotation)
            if not transform_matrix:
                return
            
            # Try to find and configure touch devices
            result = subprocess.run(["xinput", "list", "--name-only"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                touch_devices = [line.strip() for line in result.stdout.split('\n') 
                               if 'touch' in line.lower() or 'screen' in line.lower()]
                
                for device in touch_devices:
                    if device:
                        subprocess.run([
                            "xinput", "set-prop", device, "Coordinate Transformation Matrix",
                            *transform_matrix.split()
                        ], capture_output=True, text=True, timeout=3)
                
                if touch_devices:
                    print(f"✓ Configured touch coordinate transformation for rotation")
                else:
                    print("ℹ No touch devices found for coordinate transformation")
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            print("ℹ Touch coordinate transformation not available")

    def _disable_automount_dialogs(self) -> None:
        """Disable desktop auto-mount dialogs that interfere with kiosk mode."""
        try:
            import subprocess
            
            # Method 1: Disable GNOME/MATE automount notifications
            try:
                subprocess.run([
                    "gsettings", "set", "org.gnome.desktop.media-handling", "automount-open", "false"
                ], capture_output=True, timeout=3)
                subprocess.run([
                    "gsettings", "set", "org.gnome.desktop.media-handling", "autorun-never", "true"
                ], capture_output=True, timeout=3)
                print("✓ GNOME automount dialogs disabled")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
            # Method 2: Disable XFCE/LXDE automount notifications  
            try:
                subprocess.run([
                    "xfconf-query", "-c", "thunar-volman", "-p", "/automount-drives/enabled", "-s", "false"
                ], capture_output=True, timeout=3)
                subprocess.run([
                    "xfconf-query", "-c", "thunar-volman", "-p", "/automount-media/enabled", "-s", "false"
                ], capture_output=True, timeout=3)
                print("✓ XFCE automount dialogs disabled")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
            # Method 3: Disable PCManFM (LXDE file manager) automount
            try:
                subprocess.run([
                    "pcmanfm", "--set-config", "mount_on_startup", "0"
                ], capture_output=True, timeout=3)
                subprocess.run([
                    "pcmanfm", "--set-config", "mount_removable", "0"
                ], capture_output=True, timeout=3)
                print("✓ PCManFM automount dialogs disabled")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
            # Method 4: Kill any existing automount processes
            try:
                subprocess.run(["pkill", "-f", "gvfs-udisks2-volume-monitor"], capture_output=True, timeout=2)
                subprocess.run(["pkill", "-f", "udisks-daemon"], capture_output=True, timeout=2)
                print("✓ Existing automount processes terminated")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
        except Exception as e:
            print(f"⚠ Auto-mount dialog suppression failed: {e}")

    def _show_manual_rotation_config(self) -> None:
        """Show manual configuration options for persistent rotation."""
        if self.display_rotation == 0:
            return
            
        print("\n" + "=" * 60)
        print("📋 MANUAL ROTATION CONFIGURATION")
        print("=" * 60)
        print(f"For persistent {self.display_rotation * 90}° rotation across reboots:")
        print()
        print("🔧 Method 1: Boot Command Line (Recommended)")
        print("   Edit /boot/firmware/cmdline.txt and add at the end:")
        print(f"   video=DSI-1:720x1280@60,rotate={self.display_rotation * 90}")
        print()
        print("🔧 Method 2: Config.txt (Alternative)")  
        print("   Add to /boot/firmware/config.txt:")
        print(f"   display_rotate={self.display_rotation}")
        print()
        print("🔧 Method 3: Desktop Session (GUI environments)")
        print("   Add to ~/.config/autostart/screen-rotation.desktop:")
        print(f"   Exec=wlr-randr --output DSI-1 --transform {self.display_rotation * 90}")
        print()
        print("🔧 Method 4: Systemd Service (Service mode)")
        print("   ArgusPi service can be configured to apply rotation on startup")
        print("=" * 60)

    def _create_simple_mode_display(self) -> None:
        """Create the simple user-friendly display with progress and timer."""
        # Action display frame
        self.action_frame = tk.Frame(self.root, bg="black")
        self.action_frame.pack(pady=(30, 15), fill="x", padx=20)  # Increased padding
        
        # Current action label - Much larger font
        self.action_var = tk.StringVar(value=self.current_action)
        self.action_label = tk.Label(
            self.action_frame,
            textvariable=self.action_var,
            font=("Helvetica", 32),  # Doubled from 16 to 32
            fg="#cccccc",
            bg="black",
        )
        self.action_label.pack()

        # Progress and timer frame - centered layout
        self.progress_frame = tk.Frame(self.root, bg="black")
        self.progress_frame.pack(pady=(20, 30))  # Increased padding

        # Get screen dimensions for responsive sizing
        screen_width, screen_height = self._get_screen_dimensions()
        # Calculate progress bar width as percentage of screen width (60% of screen, minimum 400px)
        progress_width = max(400, int(screen_width * 0.6))  # Increased width
        progress_height = max(30, int(screen_height * 0.03))  # Scale height too

        # Progress bar - Much thicker
        style = ttk.Style()
        style.theme_use('clam')  # Use a theme that works well
        style.configure("Custom.Horizontal.TProgressbar",
                       background="#00cc00",    # Green progress bar
                       troughcolor="#333333",   # Dark background
                       borderwidth=2,           # Thicker border
                       lightcolor="#00cc00",
                       darkcolor="#008800",
                       thickness=progress_height)  # Much thicker progress bar
        
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            mode='determinate',
            length=progress_width,
            style="Custom.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(pady=(0, 15))  # Increased spacing
        
        # Timer display - Much larger font
        self.timer_var = tk.StringVar(value="00:00")
        self.timer_label = tk.Label(
            self.progress_frame,
            textvariable=self.timer_var,
            font=("Helvetica", 28, "bold"),  # Doubled from 14 to 28
            fg="#ffcc00",  # Yellow
            bg="black",
        )
        self.timer_label.pack()  # Center the timer below the progress bar

        # Progress text (files scanned) - Larger font
        self.progress_var = tk.StringVar(value="Ready")
        self.progress_label = tk.Label(
            self.root,
            textvariable=self.progress_var,
            font=("Helvetica", 24),  # Doubled from 12 to 24
            fg="#aaaaaa",
            bg="black",
        )
        self.progress_label.pack(pady=15)  # Increased padding

        # Start timer update
        self._update_timer()

    def _create_detailed_mode_display(self) -> None:
        """Create the detailed technical log display."""
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
            font=("Courier", 18)  # Doubled from 9 to 18
        )
        self.log_text.pack(fill="both", expand=True, padx=20, pady=10)

        # Scrollbar for the log text
        self.scrollbar = tk.Scrollbar(self.log_text, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")

    def _update_timer(self) -> None:
        """Update the timer display in simple mode."""
        if self.simple_mode and hasattr(self, 'timer_var'):
            try:
                if self.scan_start_time is not None:
                    # Use final scan time if scan is complete, otherwise show running time
                    if hasattr(self, 'final_scan_time') and self.final_scan_time is not None:
                        elapsed = self.final_scan_time
                    else:
                        elapsed = time.time() - self.scan_start_time
                    
                    minutes = int(elapsed // 60)
                    seconds = int(elapsed % 60)
                    self.timer_var.set(f"{minutes:02d}:{seconds:02d}")
                else:
                    self.timer_var.set("00:00")
                
                # Schedule next update
                self.root.after(1000, self._update_timer)
            except Exception:
                pass

    def update_progress(self, current: int, total: int, action: str = "") -> None:
        """Update progress bar and action text in simple mode."""
        if not self.simple_mode:
            return
            
        try:
            def update_ui():
                # Update progress bar
                if hasattr(self, 'progress_bar'):
                    if total > 0:
                        percentage = (current / total) * 100
                        self.progress_bar['value'] = percentage
                    else:
                        # Reset progress bar to 0% when total is 0 (idle state)
                        self.progress_bar['value'] = 0
                
                # Update progress text
                if hasattr(self, 'progress_var'):
                    if total > 0:
                        self.progress_var.set(f"Files scanned: {current} / {total}")
                    else:
                        self.progress_var.set("Ready")
                
                # Update action text
                if hasattr(self, 'action_var') and action:
                    self.action_var.set(action)
            
            self.root.after(0, update_ui)
        except Exception:
            pass

    def start_scan_timer(self) -> None:
        """Start the scan timer."""
        import time
        self.scan_start_time = time.time()
        self.final_scan_time = None  # Reset any previous final time

    def stop_scan_timer(self) -> None:
        """Stop the scan timer and preserve the final elapsed time."""
        if self.scan_start_time is not None:
            # Calculate and store the final elapsed time
            self.final_scan_time = time.time() - self.scan_start_time
        # Keep scan_start_time for now so timer can still display the final time
        # It will be reset when a new scan starts

    def _get_status_color(self, status: str) -> str:
        """Get the background color for a given status."""
        # Extract color from _color_map, default to blue for unknown status
        color, _ = self._color_map.get(status, ("#0066cc", ""))
        return color

    def set_status(self, status: str) -> None:
        """Update the status panel colour and label text."""
        # Track status changes and log to file if logging is available
        if hasattr(self, 'current_status_key') and self.current_status_key != status:
            if hasattr(self, '_log_callback') and self._log_callback:
                debug_msg = f"GUI Status change: {getattr(self, 'current_status_key', 'None')} → {status}"
                self._log_callback(debug_msg, "DEBUG")
        
        self.current_status_key = status  # Store current status key for screensaver restoration
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
        """Append a line of text to the log area (detailed mode only)."""
        # Only append to log in detailed mode
        if not self.simple_mode and hasattr(self, 'log_text'):
            def update() -> None:
                self.log_text.configure(state="normal")
                self.log_text.insert("end", line + "\n")
                # Auto-scroll to the end
                self.log_text.see("end")
                self.log_text.configure(state="disabled")
            try:
                self.root.after(0, update)
            except Exception:
                pass

    def _on_activity(self, event=None) -> None:
        """Handle user activity events to reset screensaver timer."""
        import time
        self.last_activity = time.time()
        if self.screensaver_active:
            self._deactivate_screensaver()

    def _check_screensaver(self) -> None:
        """Check if screensaver should be activated."""
        import time
        current_time = time.time()

        if not self.screensaver_active and self.last_activity > 0:
            idle_time = (current_time - self.last_activity) * 1000  # Convert to milliseconds
            if idle_time >= self.screensaver_timeout:
                self._activate_screensaver()

        # Schedule next check
        self.root.after(10000, self._check_screensaver)  # Check every 10 seconds

    def _activate_screensaver(self) -> None:
        """Activate the screensaver display."""
        if self.screensaver_active:
            return

        self.screensaver_active = True

        # Save current log content before hiding widgets
        try:
            if hasattr(self, 'log_text') and self.log_text:
                self.saved_log_content = self.log_text.get("1.0", "end-1c")
            else:
                self.saved_log_content = ""
        except Exception:
            self.saved_log_content = ""

        # Hide main content
        for widget in self.root.winfo_children():
            widget.place_forget()
            widget.pack_forget()

        # Create screensaver canvas
        self.screensaver_canvas = tk.Canvas(
            self.root,
            width=self.root.winfo_screenwidth(),
            height=self.root.winfo_screenheight(),
            bg="black",
            highlightthickness=0
        )
        self.screensaver_canvas.pack(fill="both", expand=True)

        # Create floating ArgusPi logo and clock
        self._create_screensaver_elements()
        self._animate_screensaver()

    def _deactivate_screensaver(self) -> None:
        """Deactivate the screensaver and restore main interface."""
        if not self.screensaver_active:
            return

        self.screensaver_active = False

        # Remove screensaver elements
        if hasattr(self, 'screensaver_canvas'):
            self.screensaver_canvas.destroy()

        # Restore main interface
        self._restore_main_interface()

    def _create_screensaver_elements(self) -> None:
        """Create screensaver display elements with status indication."""
        canvas = self.screensaver_canvas

        # Calculate initial positions
        screen_width = canvas.winfo_reqwidth()
        screen_height = canvas.winfo_reqheight()

        # Get current status info
        status_color, status_message = self._color_map.get(self.current_status_key, ("#0066cc", "Waiting for USB device…"))

        # Create floating ArgusPi logo
        self.logo_x = screen_width // 2
        self.logo_y = screen_height // 2 - 80
        self.logo_dx = random.choice([-2, -1, 1, 2])
        self.logo_dy = random.choice([-2, -1, 1, 2])

        self.screensaver_logo = canvas.create_text(
            self.logo_x, self.logo_y,
            text="ArgusPi",
            font=("Helvetica", 48, "bold"),
            fill="#00ff00",
            anchor="center"
        )

        # Create subtitle
        self.subtitle_text = canvas.create_text(
            self.logo_x, self.logo_y + 60,
            text="USB Security Scanner",
            font=("Helvetica", 32),  # Doubled from 16 to 32
            fill="#888888",
            anchor="center"
        )

        # Create status display with current status color and message
        self.status_x = screen_width // 2
        self.status_y = screen_height // 2 + 40
        self.status_bg = canvas.create_rectangle(
            self.status_x - 250, self.status_y - 25,
            self.status_x + 250, self.status_y + 25,
            fill=status_color,
            outline="white",
            width=2
        )
        
        self.status_text = canvas.create_text(
            self.status_x, self.status_y,
            text=status_message,
            font=("Helvetica", 36, "bold"),  # Doubled from 18 to 36
            fill="white",
            anchor="center"
        )

        # Add scanning animation for active scans
        if self.current_status_key == "scanning":
            self.scanning_dots = 0
            self.scanning_timer = 0

        # Create clock
        self.clock_x = screen_width // 2
        self.clock_y = screen_height - 100
        self.clock_text = canvas.create_text(
            self.clock_x, self.clock_y,
            text="",
            font=("Courier", 24, "bold"),
            fill="#0066cc",
            anchor="center"
        )

    def _animate_screensaver(self) -> None:
        """Animate screensaver elements with status awareness."""
        if not self.screensaver_active:
            return

        canvas = self.screensaver_canvas

        try:
            # Get canvas dimensions
            canvas_width = canvas.winfo_width()
            canvas_height = canvas.winfo_height()

            # Update logo position
            self.logo_x += self.logo_dx
            self.logo_y += self.logo_dy

            # Bounce off edges
            logo_bounds = canvas.bbox(self.screensaver_logo)
            if logo_bounds:
                if self.logo_x <= 50 or self.logo_x >= canvas_width - 50:
                    self.logo_dx = -self.logo_dx
                if self.logo_y <= 50 or self.logo_y >= canvas_height - 150:
                    self.logo_dy = -self.logo_dy

            # Update logo and subtitle positions
            canvas.coords(self.screensaver_logo, self.logo_x, self.logo_y)
            canvas.coords(self.subtitle_text, self.logo_x, self.logo_y + 60)

            # Update status display with current status
            status_color, status_message = self._color_map.get(self.current_status_key, ("#0066cc", "Waiting for USB device…"))
            
            # Add scanning animation dots if scanning
            if self.current_status_key == "scanning":
                if not hasattr(self, 'scanning_timer'):
                    self.scanning_timer = 0
                    self.scanning_dots = 0
                
                self.scanning_timer += 1
                if self.scanning_timer >= 10:  # Update every ~500ms (10 * 50ms frames)
                    self.scanning_timer = 0
                    self.scanning_dots = (self.scanning_dots + 1) % 4
                    dots = "." * self.scanning_dots
                    animated_message = status_message.rstrip("…") + dots
                    canvas.itemconfig(self.status_text, text=animated_message)
            else:
                # Update status text for non-scanning states
                canvas.itemconfig(self.status_text, text=status_message)
            
            # Update status background color
            canvas.itemconfig(self.status_bg, fill=status_color)

            # Update clock
            from datetime import datetime
            current_time = datetime.now().strftime("%H:%M:%S")
            current_date = datetime.now().strftime("%Y-%m-%d")
            clock_display = f"{current_date}\n{current_time}"
            canvas.itemconfig(self.clock_text, text=clock_display)

            # Schedule next animation frame
            self.root.after(50, self._animate_screensaver)  # ~20 FPS

        except Exception:
            # Handle any animation errors gracefully
            pass

    def _restore_main_interface(self) -> None:
        """Restore the main ArgusPi interface after screensaver."""
        # Log screensaver restoration if logging is available
        if hasattr(self, '_log_callback') and self._log_callback:
            debug_msg = f"Restoring interface with status: {getattr(self, 'current_status_key', 'None')}"
            self._log_callback(debug_msg, "DEBUG")
        
        # Recreate main interface elements
        # Title banner
        self.title_frame = tk.Frame(self.root, bg="black")
        self.title_frame.pack(pady=30)  # Increased padding

        # ArgusPi logo/title - Much larger for fullscreen
        self.title_label = tk.Label(
            self.title_frame,
            text="ArgusPi",
            font=("Helvetica", 72, "bold"),  # Doubled from 36 to 72
            fg="#00ff00",  # Bright green
            bg="black",
        )
        self.title_label.pack()

        # Subtitle - Larger for fullscreen
        self.subtitle_label = tk.Label(
            self.title_frame,
            text="USB Security Scanner",
            font=("Helvetica", 32),  # Doubled from 16 to 32
            fg="white",
            bg="black",
        )
        self.subtitle_label.pack()

        # Status panel - use current status key instead of trying to parse message
        status_color = self._get_status_color(self.current_status_key)
        # Get screen dimensions for responsive sizing
        screen_width, screen_height = self._get_screen_dimensions()
        status_width = max(600, int(screen_width * 0.6))  # Increased to match main init
        status_height = max(180, int(screen_height * 0.15))  # Scale height too
        self.status_frame = tk.Frame(self.root, width=status_width, height=status_height, bg=status_color)
        self.status_frame.pack(pady=40)  # Increased padding

        # Status label - Much larger font
        self.status_label = tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Helvetica", 40, "bold"),  # Doubled from 20 to 40
            fg="white",
            bg="black",
        )
        self.status_label.pack(pady=20)  # Increased padding

        # Recreate mode-specific display
        if self.simple_mode:
            self._create_simple_mode_display()
        else:
            self._create_detailed_mode_display()
            
        # Restore saved log content if in detailed mode
        if not self.simple_mode and hasattr(self, 'saved_log_content') and self.saved_log_content:
            try:
                self.log_text.configure(state="normal")
                self.log_text.insert("1.0", self.saved_log_content)
                self.log_text.see("end")  # Scroll to the end
                self.log_text.configure(state="disabled")
            except Exception:
                pass

    def run(self) -> None:
        """Enter the Tk main loop."""
        import time
        self.last_activity = time.time()
        
        # Schedule geometry fix after GUI is fully loaded (fixes half-screen issues)
        self.root.after(1000, self._fix_geometry_after_load)
        
        # Start screensaver checker
        self.root.after(10000, self._check_screensaver)
        
        # Start focus restoration to prevent dialogs from stealing focus
        self.root.after(2000, self._restore_focus)

        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            # Gracefully exit on Ctrl-C
            pass

    def _restore_focus(self) -> None:
        """Periodically restore focus to prevent other windows from appearing."""
        try:
            # Bring ArgusPi window back to front and grab focus
            self.root.lift()
            self.root.focus_force()
            
            # Schedule next focus restoration in 5 seconds
            self.root.after(5000, self._restore_focus)
            
        except Exception:
            # Continue trying to restore focus even if there's an error
            self.root.after(5000, self._restore_focus)

    def _fix_geometry_after_load(self) -> None:
        """Simple one-time geometry fix after GUI is fully loaded."""
        try:
            # Just ensure we're still in fullscreen mode - don't fight with window manager
            self.root.attributes("-fullscreen", True)
            
            # Log final dimensions for debugging
            try:
                actual_width = self.root.winfo_width() 
                actual_height = self.root.winfo_height()
                print(f"✓ Final window size: {actual_width}x{actual_height}")
            except:
                pass
                
        except Exception as e:
            print(f"⚠ Geometry fix failed: {e}")
            # Don't retry - just accept whatever we get


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
        self.clamav_cmd: str = "clamdscan"  # Use daemon for better performance
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
        # Track devices currently being processed to prevent duplicates
        self.processing_devices = set()
        self.processing_lock = Lock()
        # Track current scan results for persistent display
        self.current_scan_result = None  # 'clean', 'infected', 'error', or None
        self.current_device_node = None  # Track which device was scanned
        self.result_lock = Lock()
        # Initialise LED after config loaded
        self._init_led()
        # Define colours for different statuses
        self.status_colors = {
            "waiting": (0.0, 0.0, 1.0),      # blue
            "scanning": (1.0, 1.0, 0.0),     # yellow
            "clean": (0.0, 1.0, 0.0),        # green
            "infected": (1.0, 0.0, 0.0),     # red
            # Persistent result statuses
            "scan_clean": (0.0, 1.0, 0.0),   # green - clean result
            "scan_infected": (1.0, 0.0, 0.0), # red - infected result  
            "scan_error": (1.0, 0.5, 0.0),   # orange - error result
        }
        # Initialise GUI if enabled
        if self.use_gui:
            try:
                self.gui = ArgusPiGUI(
                    simple_mode=self.gui_simple_mode,
                    display_rotation=self.display_rotation
                )
                # Connect GUI to logging system for debug output
                self.gui._log_callback = self.log
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
        self.clamav_cmd = data.get("clamav_cmd", "clamdscan")  # Default to daemon
        # LED configuration
        self.use_led = bool(data.get("use_led", False))
        pins = data.get("led_pins", None)
        if pins and all(k in pins for k in ("red", "green", "blue")):
            self.led_pins = {"red": int(pins["red"]), "green": int(pins["green"]), "blue": int(pins["blue"])}
        # GUI configuration
        self.use_gui = bool(data.get("use_gui", False))
        self.gui_simple_mode = bool(data.get("gui_simple_mode", False))
        self.display_rotation = int(data.get("display_rotation", 0))
        # Screensaver configuration
        self.use_screensaver = bool(data.get("use_screensaver", True))
        self.screensaver_timeout = int(data.get("screensaver_timeout", 300))  # Default 5 minutes in seconds
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
            self.log(f"ArgusPi RGB LED initialized on pins "
                     f"R:{self.led_pins['red']} G:{self.led_pins['green']} "
                     f"B:{self.led_pins['blue']}")
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
            if status in ("error", "scan_error"):
                self.blink_error()
            else:
                colour = self.status_colors.get(status)
                if colour:
                    self.set_led_color(*colour)
        # Always update GUI if present
        if self.gui:
            self.gui.set_status(status)
            # Reset progress bar when returning to waiting state
            if status == "waiting" and self.gui.simple_mode:
                self.gui.update_progress(0, 0, "Waiting for USB device…")

    @staticmethod
    def compute_hash(file_path: str) -> str:
        """Compute SHA-256 hash of a file in a memory-efficient way.

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
        current_file = 0

        # Optimization: For local-only scanning, do a bulk scan first
        if self.use_clamav and self.api_key is None:
            return self._scan_path_bulk_local(mount_point)
        else:
            return self._scan_path_individual(mount_point)

    def _scan_path_bulk_local(self, mount_point: str) -> None:
        """Optimized bulk local scanning for offline mode."""
        self.log(f"Starting bulk ClamAV scan of {mount_point}", "INFO")
        
        # Count files first for progress tracking
        total_files = 0
        for root, dirs, files in os.walk(mount_point):
            total_files += len(files)
        
        if self.gui:
            self.gui.set_status("scanning")
            self.gui.update_progress(0, total_files, "Scanning all files with ClamAV...")
        
        try:
            # Run bulk scan on entire mount point
            result = subprocess.run(
                [self.clamav_cmd, "--infected", "--recursive", "--no-summary", mount_point],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600  # 10 minute timeout for bulk scan
            )
            
            infected_files = []
            if result.stdout:
                # Parse infected files from output
                for line in result.stdout.strip().split('\n'):
                    if line and 'FOUND' in line:
                        infected_file = line.split(':')[0].strip()
                        infected_files.append(infected_file)
            
            # Update final status
            if infected_files:
                self.log(f"ClamAV detected {len(infected_files)} infected files", "WARN")
                for infected_file in infected_files:
                    self.log(f"INFECTED: {infected_file}", "WARN")
                if self.gui:
                    self.gui.set_status("scan_infected")
            elif result.returncode == 2:
                self.log("ClamAV scan completed with errors", "WARN")
                if self.gui:
                    self.gui.set_status("scan_error")
            else:
                self.log(f"ClamAV scan completed - {total_files} files clean", "INFO")
                if self.gui:
                    self.gui.set_status("scan_clean")
                    
        except subprocess.TimeoutExpired:
            self.log("ClamAV bulk scan timed out", "ERROR")
            if self.gui:
                self.gui.set_status("scan_error")
        except Exception as e:
            self.log(f"ClamAV bulk scan failed: {e}", "ERROR")
            if self.gui:
                self.gui.set_status("scan_error")

    def _scan_path_individual(self, mount_point: str) -> None:
        """Individual file scanning for online mode or when bulk scan not suitable."""
        infected_found = False
        error_occurred = False
        total_files = 0
        infected_files = 0
        current_file = 0

        # Update GUI with scanning action and start timer
        if self.gui:
            self.gui.start_scan_timer()
            if self.gui.simple_mode:
                self.gui.update_progress(0, 0, "Counting files...")

        # Count total files first for progress tracking
        if self.gui and self.gui.simple_mode:
            try:
                for root, dirs, files in os.walk(mount_point):
                    total_files += len(files)
            except Exception:
                total_files = 0
            
            self.gui.update_progress(0, total_files, "Starting scan...")

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
                    current_file += 1

                    # Update progress
                    if self.gui and self.gui.simple_mode:
                        action = f"Scanning: {name}"
                        if self.use_clamav:
                            action += " (local scan)"
                        self.gui.update_progress(current_file, total_files, action)

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
                        if self.gui and self.gui.simple_mode:
                            self.gui.update_progress(current_file, total_files, f"Checking cloud: {name}")
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
        """Mount the given block device read-only with secure options.

        Returns the mount path or None if mounting failed.
        """
        device_name = os.path.basename(device_node)
        mount_point = os.path.join(self.mount_base, device_name)
        
        # Check if device is already mounted somewhere
        try:
            mount_check = subprocess.run(
                ["mount"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            mount_lines = mount_check.stdout.strip().split('\n')
            
            for line in mount_lines:
                if device_node in line:
                    # Device is already mounted, extract the mount point
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == device_node:
                        existing_mount = parts[2]
                        self.log(f"Device {device_node} already mounted at {existing_mount}. Using existing mount.")
                        # Track this mount for cleanup (but don't unmount it ourselves)
                        with self.mount_lock:
                            self.active_mounts.add((device_node, existing_mount))
                        return existing_mount
                        
            # Also check /proc/mounts as a backup
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    if device_node in line:
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == device_node:
                            existing_mount = parts[1]
                            self.log(f"Found {device_node} in /proc/mounts at {existing_mount}. Using existing mount.")
                            with self.mount_lock:
                                self.active_mounts.add((device_node, existing_mount))
                            return existing_mount
                            
        except (subprocess.CalledProcessError, IOError) as e:
            # If mount command or /proc/mounts fails, proceed with normal mounting
            self.log(f"Could not check existing mounts: {e}", "DEBUG")
            pass
        
        # Device not mounted, proceed with our own mounting
        os.makedirs(mount_point, exist_ok=True)
        
        # Put device into read-only state (ignore errors)
        subprocess.run(["/sbin/hdparm", "-r1", device_node], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Try to mount with safe options
        try:
            result = subprocess.run(
                [
                    "/bin/mount",
                    "-o",
                    "ro,noexec,nosuid,nodev,sync",  # sync to avoid write caching
                    device_node,
                    mount_point,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            # Track this mount for cleanup
            with self.mount_lock:
                self.active_mounts.add((device_node, mount_point))
            return mount_point
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            self.log(f"Failed to mount {device_node}: {error_msg}", "ERROR")
            
            # If device is already mounted, try to find where it's mounted
            if "already mounted" in error_msg.lower() or "busy" in error_msg.lower():
                self.log(f"Device appears to be already mounted, re-checking mount points", "DEBUG")
                try:
                    mount_check = subprocess.run(
                        ["mount"], 
                        capture_output=True, 
                        text=True, 
                        check=True
                    )
                    mount_lines = mount_check.stdout.strip().split('\n')
                    
                    for line in mount_lines:
                        if device_node in line:
                            parts = line.split()
                            if len(parts) >= 3 and parts[0] == device_node:
                                existing_mount = parts[2]
                                self.log(f"Found {device_node} already mounted at {existing_mount}, using it", "INFO")
                                # Track this mount for cleanup (but don't unmount it ourselves)
                                with self.mount_lock:
                                    self.active_mounts.add((device_node, existing_mount))
                                return existing_mount
                except subprocess.CalledProcessError:
                    pass
            
            # Reset read-only flag on failure
            subprocess.run(["/sbin/hdparm", "-r0", device_node], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return None

    def unmount_device(self, device_node: str, mount_point: str) -> None:
        """Unmount and clean up a device."""
        try:
            # Check if this is our mount point (under /mnt/arguspi) or a system mount
            is_our_mount = mount_point.startswith(self.mount_base)
            
            if is_our_mount:
                # This is our mount, safe to unmount
                subprocess.run(["/bin/umount", mount_point], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Remove mount directory if empty
                try:
                    os.rmdir(mount_point)
                except OSError:
                    pass
                self.log(f"Unmounted ArgusPi mount: {mount_point}")
            else:
                # This was a pre-existing system mount, leave it alone
                self.log(f"Leaving system mount intact: {mount_point}")
        finally:
            # Always reset read-only flag so the user can use the drive again
            subprocess.run(["/sbin/hdparm", "-r0", device_node], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Remove from active mounts tracking
            with self.mount_lock:
                self.active_mounts.discard((device_node, mount_point))

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
        
        # Check if we're already processing this device
        with self.processing_lock:
            if device_node in self.processing_devices:
                self.log(f"Device {device_node} is already being processed, skipping duplicate", "DEBUG")
                return
            # Mark device as being processed
            self.processing_devices.add(device_node)
        
        try:
            # Debug: Log device information
            fs_type = device.get("ID_FS_TYPE", "unknown")
            device_label = device.get("ID_FS_LABEL", "unlabeled")
            device_uuid = device.get("ID_FS_UUID", "no-uuid")
            
            self.log(f"ArgusPi detected USB device {device_node} (fs: {fs_type}, label: {device_label})")
            self.log(f"Device details - UUID: {device_uuid}, Bus: {device.get('ID_BUS', 'unknown')}", "DEBUG")
            
            # Update action for simple mode
            if self.gui and self.gui.simple_mode:
                self.gui.update_progress(0, 0, "Mounting USB device...")
            
            mount_point = self.mount_device(device_node)
            if mount_point:
                # Set LED to scanning state
                self.update_status("scanning")
                
                # Update action for simple mode
                if self.gui and self.gui.simple_mode:
                    self.gui.update_progress(0, 0, "Preparing to scan...")
                
                try:
                    self.log(f"Mounted {device_node} at {mount_point}. Beginning ArgusPi scan.")
                    result = self.scan_path(mount_point)
                    # Determine persistent result based on scan outcome
                    with self.result_lock:
                        self.current_device_node = device_node
                        if result is None:
                            self.current_scan_result = "error"
                            self.update_status("scan_error")
                        elif result is True:
                            self.current_scan_result = "infected" 
                            self.update_status("scan_infected")
                        else:
                            self.current_scan_result = "clean"
                            self.update_status("scan_clean")
                            
                        # Stop timer and show completion in simple mode
                        if self.gui:
                            self.gui.stop_scan_timer()
                            if self.gui.simple_mode:
                                if result is None:
                                    self.gui.update_progress(0, 0, "Scan failed - Error occurred")
                                elif result is True:
                                    self.gui.update_progress(100, 100, "⚠️ THREATS DETECTED!")
                                else:
                                    self.gui.update_progress(100, 100, "✅ Scan complete - Device is clean")
                            
                finally:
                    # Update action for unmounting
                    if self.gui and self.gui.simple_mode:
                        self.gui.update_progress(0, 0, "Unmounting USB device...")
                    
                    self.unmount_device(device_node, mount_point)
                    self.log(f"ArgusPi completed scan of {device_node} and unmounted.")
                    # Don't return to waiting - keep showing result until USB removed
            else:
                self.log(f"ArgusPi skipping scan for {device_node} due to mount failure.")
                with self.result_lock:
                    self.current_device_node = device_node
                    self.current_scan_result = "error"
                self.update_status("scan_error")
                
        finally:
            # Remove device from processing set
            with self.processing_lock:
                self.processing_devices.discard(device_node)

    def handle_device_removal(self, device) -> None:
        """Handle USB device removal and reset status to waiting."""
        device_node = device.device_node
        
        # Clean up processing tracker
        with self.processing_lock:
            self.processing_devices.discard(device_node)
        
        with self.result_lock:
            # Check if this device matches our tracked scan result
            if self.current_device_node == device_node or self.current_scan_result is not None:
                self.log(f"USB device {device_node} removed. Resetting to waiting state.", "INFO")
                self.current_scan_result = None
                self.current_device_node = None
                # Reset timer state when device is removed
                if self.gui:
                    self.gui.scan_start_time = None
                    self.gui.final_scan_time = None
                    # Reset progress bar and action text in simple mode
                    if self.gui.simple_mode:
                        self.gui.update_progress(0, 0, "Waiting for USB device…")
                self.update_status("waiting")

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
                # Handle both 'add' and 'remove' events for USB devices
                if device.action == "add":
                    # Only handle devices from the USB bus
                    if device.get("ID_BUS") != "usb":
                        continue
                    # Skip devices with no filesystem type (e.g. raw partitions)
                    if "ID_FS_TYPE" not in device:
                        continue
                    # Handle scanning in a new thread to avoid blocking further events
                    t = Thread(target=self.handle_device, args=(device,), daemon=True)
                    t.start()
                elif device.action == "remove":
                    # Handle USB device removal
                    if device.get("ID_BUS") == "usb":
                        self.handle_device_removal(device)
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
    """Main entry point for ArgusPi scanning station daemon."""
    try:
        station = ArgusPiStation()
    except Exception as err:
        print(f"ArgusPi Error: {err}")
        sys.exit(1)
    station.run()


if __name__ == "__main__":
    main()

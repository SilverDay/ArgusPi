#!/usr/bin/env python3
"""
ArgusPi GUI Diagnostic Script
============================

This script helps diagnose GUI startup issues when ArgusPi is running as a systemd service.
Run this script to check:
1. Display environment variables
2. X11 server availability  
3. Tkinter GUI creation
4. Window manager compatibility
"""

import os
import sys
import subprocess

def check_environment():
    """Check GUI-related environment variables."""
    print("🔍 Environment Variables:")
    env_vars = [
        'DISPLAY',
        'XAUTHORITY', 
        'XDG_RUNTIME_DIR',
        'XDG_SESSION_TYPE',
        'WAYLAND_DISPLAY',
        'HOME',
        'USER'
    ]
    
    for var in env_vars:
        value = os.environ.get(var, 'Not set')
        print(f"  {var}: {value}")
    print()

def check_x11_server():
    """Check if X11 server is accessible."""
    print("🖥️ X11 Server Check:")
    try:
        result = subprocess.run(['xset', 'q'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("  ✓ X11 server is accessible")
            # Parse display info
            lines = result.stdout.split('\n')
            for line in lines[:3]:
                if line.strip():
                    print(f"    {line.strip()}")
        else:
            print("  ✗ X11 server not accessible")
            print(f"    Error: {result.stderr}")
    except FileNotFoundError:
        print("  ⚠ xset command not found (installing x11-xserver-utils may help)")
    except subprocess.TimeoutExpired:
        print("  ✗ X11 server check timed out")
    except Exception as e:
        print(f"  ✗ X11 server check failed: {e}")
    print()

def check_tkinter():
    """Test Tkinter GUI creation."""
    print("🎯 Tkinter GUI Test:")
    try:
        import tkinter as tk
        print("  ✓ Tkinter module imported successfully")
        
        # Try to create a root window
        root = tk.Tk()
        print("  ✓ Tkinter root window created")
        
        # Try to get screen dimensions
        width = root.winfo_screenwidth()
        height = root.winfo_screenheight()
        print(f"  ✓ Screen dimensions: {width}x{height}")
        
        # Try fullscreen mode
        try:
            root.attributes("-fullscreen", True)
            print("  ✓ Fullscreen mode supported")
            root.attributes("-fullscreen", False)
        except Exception as e:
            print(f"  ⚠ Fullscreen mode failed: {e}")
        
        # Clean up
        root.destroy()
        print("  ✓ Tkinter test completed successfully")
        
    except ImportError as e:
        print(f"  ✗ Tkinter import failed: {e}")
        print("    Install with: sudo apt-get install python3-tk")
    except Exception as e:
        print(f"  ✗ Tkinter GUI test failed: {e}")
    print()

def check_desktop_session():
    """Check desktop session and window manager."""
    print("🖱️ Desktop Session Check:")
    
    # Check if desktop session is running
    try:
        result = subprocess.run(['pgrep', '-f', 'lxsession|gnome-session|xfce4-session'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("  ✓ Desktop session is running")
        else:
            print("  ⚠ No desktop session detected")
    except Exception as e:
        print(f"  ⚠ Desktop session check failed: {e}")
    
    # Check for autologin
    try:
        with open('/etc/systemd/system/getty@tty1.service.d/autologin.conf', 'r') as f:
            content = f.read()
            if 'autologin' in content.lower():
                print("  ✓ Autologin appears to be configured")
            else:
                print("  ⚠ Autologin configuration unclear")
    except FileNotFoundError:
        print("  ⚠ Autologin configuration not found")
        print("    Configure with: sudo raspi-config → Boot Options → Desktop Autologin")
    except Exception as e:
        print(f"  ⚠ Autologin check failed: {e}")
    print()

def check_systemd_service():
    """Check ArgusPi systemd service configuration."""
    print("⚙️ SystemD Service Check:")
    
    service_path = "/etc/systemd/system/arguspi.service"
    try:
        with open(service_path, 'r') as f:
            content = f.read()
            
        print("  ✓ ArgusPi service file exists")
        
        # Check for GUI environment variables
        gui_env_vars = ['DISPLAY=', 'XAUTHORITY=', 'XDG_RUNTIME_DIR=']
        missing_vars = []
        for var in gui_env_vars:
            if var not in content:
                missing_vars.append(var)
        
        if not missing_vars:
            print("  ✓ GUI environment variables are configured")
        else:
            print(f"  ⚠ Missing environment variables: {missing_vars}")
            
        # Check target
        if 'graphical.target' in content:
            print("  ✓ Service targets graphical.target")
        else:
            print("  ⚠ Service may not target graphical.target")
            
    except FileNotFoundError:
        print(f"  ✗ Service file not found: {service_path}")
    except Exception as e:
        print(f"  ⚠ Service check failed: {e}")
    print()

def main():
    """Run all diagnostic checks."""
    print("=" * 60)
    print("    ArgusPi GUI Diagnostic Tool")
    print("=" * 60)
    print()
    
    check_environment()
    check_x11_server() 
    check_tkinter()
    check_desktop_session()
    check_systemd_service()
    
    print("=" * 60)
    print("📋 Diagnostic Complete")
    print()
    print("If issues are found:")
    print("• Missing autologin: sudo raspi-config → Boot Options → Desktop Autologin")
    print("• Missing Tkinter: sudo apt-get install python3-tk")  
    print("• X11 issues: Check if desktop environment is running")
    print("• Service issues: Check /etc/systemd/system/arguspi.service")
    print("=" * 60)

if __name__ == "__main__":
    main()
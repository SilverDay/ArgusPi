#!/usr/bin/env python3
"""
ArgusPi Autostart Diagnostic Script
This script helps diagnose issues with the desktop autostart file creation.
"""

import os
import pwd
import sys
from pathlib import Path

def check_user_detection():
    """Check user detection logic."""
    print("=== User Detection Diagnostics ===")
    
    # Check SUDO_USER
    sudo_user = os.environ.get('SUDO_USER')
    print(f"SUDO_USER environment variable: {sudo_user}")
    
    # Check current USER
    current_user = os.environ.get('USER')
    print(f"USER environment variable: {current_user}")
    
    # Check effective user
    try:
        import pwd
        effective_user = pwd.getpwuid(os.geteuid()).pw_name
        print(f"Effective user (os.geteuid()): {effective_user}")
    except Exception as e:
        print(f"Error getting effective user: {e}")
    
    # Test the get_desktop_user logic
    print("\n--- Testing get_desktop_user logic ---")
    
    try:
        # Try SUDO_USER first
        real_user = os.environ.get('SUDO_USER')
        if real_user and real_user != 'root':
            user_info = pwd.getpwnam(real_user)
            print(f"✓ SUDO_USER method: {real_user} (UID: {user_info.pw_uid}, Home: {user_info.pw_dir})")
            return real_user, user_info.pw_uid, user_info.pw_gid, user_info.pw_dir
    except Exception as e:
        print(f"✗ SUDO_USER method failed: {e}")
    
    # Try 'pi' user
    try:
        pi_user = pwd.getpwnam("pi")
        print(f"✓ 'pi' user method: pi (UID: {pi_user.pw_uid}, Home: {pi_user.pw_dir})")
        return "pi", pi_user.pw_uid, pi_user.pw_gid, pi_user.pw_dir
    except KeyError as e:
        print(f"✗ 'pi' user method failed: {e}")
    
    # Look for regular users
    print("--- Searching for regular users (UID >= 1000) ---")
    try:
        found_users = []
        for user in pwd.getpwall():
            if user.pw_uid >= 1000 and user.pw_uid < 65534:
                if user.pw_dir.startswith('/home/'):
                    found_users.append(user)
                    print(f"  Found: {user.pw_name} (UID: {user.pw_uid}, Home: {user.pw_dir})")
        
        if found_users:
            user = found_users[0]  # Use first found
            print(f"✓ Regular user method: {user.pw_name}")
            return user.pw_name, user.pw_uid, user.pw_gid, user.pw_dir
    except Exception as e:
        print(f"✗ Regular user search failed: {e}")
    
    # Final fallback
    current_user = os.environ.get('USER', 'pi')
    print(f"✓ Fallback method: {current_user}")
    return current_user, 1000, 1000, f"/home/{current_user}"

def check_autostart_locations():
    """Check for existing autostart files."""
    print("\n=== Autostart File Locations ===")
    
    # Get user info
    username, uid, gid, homedir = check_user_detection()
    
    # Check expected location
    expected_path = os.path.join(homedir, ".config", "autostart", "arguspi.desktop")
    print(f"\nExpected autostart file: {expected_path}")
    
    if os.path.exists(expected_path):
        print("✓ Autostart file exists!")
        try:
            with open(expected_path, 'r') as f:
                content = f.read()
                print("Content:")
                print(content)
        except Exception as e:
            print(f"✗ Could not read file: {e}")
    else:
        print("✗ Autostart file does not exist")
        
        # Check if directories exist
        config_dir = os.path.join(homedir, ".config")
        autostart_dir = os.path.join(homedir, ".config", "autostart")
        
        print(f"\nDirectory checks:")
        print(f"  {homedir}: {'✓' if os.path.exists(homedir) else '✗'}")
        print(f"  {config_dir}: {'✓' if os.path.exists(config_dir) else '✗'}")
        print(f"  {autostart_dir}: {'✓' if os.path.exists(autostart_dir) else '✗'}")
    
    # Search for any arguspi.desktop files
    print(f"\n--- Searching for arguspi.desktop files ---")
    home_path = Path(homedir)
    if home_path.exists():
        for desktop_file in home_path.rglob("arguspi.desktop"):
            print(f"Found: {desktop_file}")
    
    # Check common autostart locations
    common_locations = [
        "/home/pi/.config/autostart/arguspi.desktop",
        f"/home/{username}/.config/autostart/arguspi.desktop",
        "/etc/xdg/autostart/arguspi.desktop",
    ]
    
    print(f"\n--- Checking common locations ---")
    for location in common_locations:
        if os.path.exists(location):
            print(f"✓ Found: {location}")
        else:
            print(f"✗ Not found: {location}")

def create_autostart_manually():
    """Create autostart file manually for testing."""
    print("\n=== Manual Autostart Creation ===")
    
    username, uid, gid, homedir = check_user_detection()
    
    # Create autostart directory
    autostart_dir = os.path.join(homedir, ".config", "autostart")
    config_dir = os.path.join(homedir, ".config")
    
    try:
        os.makedirs(autostart_dir, exist_ok=True)
        print(f"✓ Created directory: {autostart_dir}")
    except Exception as e:
        print(f"✗ Could not create directory: {e}")
        return False
    
    # Create desktop entry
    desktop_entry_path = os.path.join(autostart_dir, "arguspi.desktop")
    desktop_entry_content = f"""[Desktop Entry]
Type=Application
Name=ArgusPi USB Security Scanner
Exec=python3 /usr/local/bin/arguspi_scan_station.py
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Comment=ArgusPi USB Security Scanner GUI
"""
    
    try:
        with open(desktop_entry_path, "w") as f:
            f.write(desktop_entry_content)
        print(f"✓ Created autostart file: {desktop_entry_path}")
        
        # Set permissions
        try:
            os.chown(desktop_entry_path, uid, gid)
            os.chown(autostart_dir, uid, gid)
            os.chown(config_dir, uid, gid)
            print(f"✓ Set ownership to {username}:{gid}")
        except Exception as e:
            print(f"⚠ Warning: Could not set ownership: {e}")
        
        return True
        
    except Exception as e:
        print(f"✗ Could not create autostart file: {e}")
        return False

def main():
    """Main diagnostic function."""
    print("ArgusPi Autostart Diagnostic Script")
    print("===================================\n")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠ Warning: Not running as root. Some checks may fail.")
        print("  For full diagnostics, run: sudo python3 debug_autostart.py\n")
    
    # Run diagnostics
    check_user_detection()
    check_autostart_locations()
    
    # Offer to create manually
    if len(sys.argv) > 1 and sys.argv[1] == "--create":
        print("\n" + "="*50)
        create_autostart_manually()
    else:
        print("\n" + "="*50)
        print("To attempt manual creation, run:")
        print("sudo python3 debug_autostart.py --create")

if __name__ == "__main__":
    main()
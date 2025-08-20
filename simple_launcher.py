#!/usr/bin/env python3
"""
Simple Launcher for Dṛśya Security Monitor
Replace your existing simple_launcher.py with this code
"""

import subprocess
import sys
import time
import webbrowser
from pathlib import Path

def main():
    print("=" * 60)
    print("🛡️  DṚŚYA SECURITY MONITOR LAUNCHER")
    print("=" * 60)
    print("\nSelect Mode:")
    print("1. 🛡️  Lenient Mode (Basic monitoring)")
    print("2. ⚔️  Strict Mode (Advanced features)")
    print("-" * 60)
    
    choice = input("\nEnter choice (1 or 2): ").strip()
    
    if choice == "2":
        mode = "--strict"
        mode_name = "strict"
        print("\n⚔️  STRICT MODE SELECTED")
        print("Premium features enabled:")
        print("  • Auto-kill high priority threats")
        print("  • Configurable refresh intervals")
        print("  • Whitelist management")
        print("  • Security summary & PDF export")
    else:
        mode = "--lenient"
        mode_name = "lenient"
        print("\n🛡️  LENIENT MODE SELECTED")
        print("Basic monitoring enabled")
    
    print("-" * 60)
    print("🚀 Starting Dṛśya Security Monitor...")
    
    # Find the monitor script
    script_dir = Path(__file__).parent
    monitor_script = script_dir / "drsya_monitor.py"
    
    if not monitor_script.exists():
        print(f"❌ Error: drsya_monitor.py not found in {script_dir}")
        print("Make sure drsya_monitor.py is in the same directory")
        sys.exit(1)
    
    # Launch the monitor
    try:
        cmd = [sys.executable, str(monitor_script), mode, "--port", "5000"]
        print(f"💻 Command: {' '.join(cmd)}")
        print("-" * 60)
        
        # Start the process
        process = subprocess.Popen(cmd)
        
        # Give it time to start
        print("⏳ Starting server...")
        time.sleep(3)
        
        # Open browser
        url = f"http://localhost:5000?mode={mode_name}"
        print(f"🌐 Opening dashboard: {url}")
        webbrowser.open(url)
        
        print("=" * 60)
        print("✅ Dṛśya is running!")
        print("📊 Dashboard should be open in your browser")
        print("🛑 Press Ctrl+C here to stop monitoring")
        print("=" * 60)
        
        # Wait for the process
        process.wait()
        
    except KeyboardInterrupt:
        print("\n" + "=" * 60)
        print("⏹️  Stopping Dṛśya...")
        process.terminate()
        time.sleep(1)
        print("✅ Dṛśya stopped successfully")
        print("=" * 60)
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\n💡 Troubleshooting:")
        print("1. Make sure dependencies are installed:")
        print("   pip install flask flask-socketio psutil")
        print("2. Check if port 5000 is available")
        print("3. Try running directly:")
        print(f"   python3 drsya_monitor.py {mode}")

if __name__ == "__main__":
    main()

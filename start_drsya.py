#!/usr/bin/env python3
"""
Drsya Security Monitor - Fixed Startup Script
Handles mode selection with fallback to terminal mode
"""

import sys
import subprocess
import os
from pathlib import Path

def show_terminal_mode_selection():
    """Show mode selection in terminal with enhanced UI"""
    os.system('clear')  # Clear terminal
    
    print("=" * 70)
    print("🛡️  Dṛśya Security Monitor - Enhanced Edition v2.0")
    print("=" * 70)
    print()
    print("📋 MONITORING MODE SELECTION:")
    print()
    
    # Lenient Mode
    print("┌─" + "─" * 65 + "─┐")
    print("│ 1. 🛡️  LENIENT MODE (Recommended for Daily Use)              │")
    print("├─" + "─" * 65 + "─┤")
    print("│ ✓ Monitor and report threats only                           │")
    print("│ ✓ Safe for continuous operation                             │")
    print("│ ✓ Manual threat response required                           │")
    print("│ ✓ Basic protection features                                 │")
    print("│ ✓ Suitable for workstations and daily use                   │")
    print("│ ✓ Low system resource usage                                 │")
    print("└─" + "─" * 65 + "─┘")
    print()
    
    # Strict Mode
    print("┌─" + "─" * 65 + "─┐")
    print("│ 2. ⚔️  STRICT MODE (Enhanced Security Protocol)             │")
    print("├─" + "─" * 65 + "─┤")
    print("│ ⚡ Auto-terminate suspicious processes                       │")
    print("│ ⚡ Advanced configuration options                            │")
    print("│ ⚡ Protection scoring system (0-100)                         │")
    print("│ ⚡ PDF report generation                                     │")
    print("│ ⚡ Screen capture protection                                 │")
    print("│ ⚡ Clipboard monitoring                                      │")
    print("│ ⚡ Maximum security features                                 │")
    print("└─" + "─" * 65 + "─┘")
    print()
    
    print("🔧 ADDITIONAL OPTIONS:")
    print("3. 🌐 Open Web Dashboard Only")
    print("4. ❌ Exit")
    print()
    print("=" * 70)
    
    while True:
        try:
            choice = input("🎯 Enter your choice (1-4): ").strip()
            
            if choice == "1":
                print("\n✅ Lenient Mode selected!")
                print("🚀 Starting secure monitoring...")
                return "lenient"
            elif choice == "2":
                print("\n⚔️  Strict Mode selected!")
                print("🚀 Starting enhanced security monitoring...")
                return "strict"
            elif choice == "3":
                print("\n🌐 Opening web dashboard...")
                return "web-only"
            elif choice == "4":
                print("\n👋 Goodbye!")
                sys.exit(0)
            else:
                print("❌ Invalid choice. Please enter 1, 2, 3, or 4.")
        except KeyboardInterrupt:
            print("\n\n🛑 Setup cancelled by user")
            sys.exit(0)
        except EOFError:
            print("\n\n🛑 Setup cancelled")
            sys.exit(0)

def launch_web_dashboard():
    """Launch just the web dashboard"""
    import webbrowser
    import time
    
    print("🌐 Opening web dashboard in browser...")
    print("📍 URL: http://localhost:5000")
    print("💡 Make sure Drsya is running in another terminal!")
    
    try:
        webbrowser.open("http://localhost:5000")
        print("✅ Browser opened successfully!")
    except Exception as e:
        print(f"❌ Failed to open browser: {e}")
        print("📝 Please manually open: http://localhost:5000")

def check_gui_available():
    """Check if GUI is available"""
    try:
        import tkinter
        # Try to create a simple window to test
        root = tkinter.Tk()
        root.withdraw()  # Hide the window
        root.destroy()
        return True
    except Exception:
        return False

def launch_gui_mode_selector():
    """Launch GUI mode selector"""
    try:
        import tkinter as tk
        from tkinter import messagebox
        
        class QuickLauncher:
            def __init__(self):
                self.root = tk.Tk()
                self.root.title("Dṛśya Security Monitor")
                self.root.geometry("600x500")
                self.root.configure(bg='#0a0e16')
                self.root.resizable(False, False)
                
                self.selected_mode = None
                self.setup_ui()
                self.center_window()
                
            def center_window(self):
                self.root.update_idletasks()
                x = (self.root.winfo_screenwidth() // 2) - 300
                y = (self.root.winfo_screenheight() // 2) - 250
                self.root.geometry(f"600x500+{x}+{y}")
                
            def setup_ui(self):
                # Header
                header_frame = tk.Frame(self.root, bg='#0a0e16')
                header_frame.pack(pady=30)
                
                title_label = tk.Label(header_frame, 
                                      text="Dṛśya", 
                                      font=('Arial', 36, 'bold'),
                                      fg='#3b82f6', 
                                      bg='#0a0e16')
                title_label.pack()
                
                subtitle_label = tk.Label(header_frame, 
                                         text="Security Monitor - Enhanced Edition v2.0", 
                                         font=('Arial', 12),
                                         fg='#d1d5db', 
                                         bg='#0a0e16')
                subtitle_label.pack(pady=(5, 0))
                
                version_label = tk.Label(header_frame, 
                                        text="Advanced Threat Detection & System Analysis", 
                                        font=('Arial', 10),
                                        fg='#9ca3af', 
                                        bg='#0a0e16')
                version_label.pack(pady=(5, 20))
                
                # Mode buttons
                buttons_frame = tk.Frame(self.root, bg='#0a0e16')
                buttons_frame.pack(pady=20, padx=60, fill='x')
                
                # Lenient Mode Button
                lenient_btn = tk.Button(buttons_frame,
                                       text="🛡️ LENIENT MODE\nRecommended for Daily Use",
                                       font=('Arial', 14, 'bold'),
                                       bg='#10b981',
                                       fg='white',
                                       command=lambda: self.select_mode('lenient'),
                                       pady=20,
                                       relief='flat',
                                       cursor='hand2')
                lenient_btn.pack(fill='x', pady=10)
                
                # Strict Mode Button
                strict_btn = tk.Button(buttons_frame,
                                      text="⚔️ STRICT MODE\nEnhanced Security Features",
                                      font=('Arial', 14, 'bold'),
                                      bg='#ef4444',
                                      fg='white',
                                      command=lambda: self.select_mode('strict'),
                                      pady=20,
                                      relief='flat',
                                      cursor='hand2')
                strict_btn.pack(fill='x', pady=10)
                
                # Web Dashboard Button
                web_btn = tk.Button(buttons_frame,
                                   text="🌐 WEB DASHBOARD ONLY\nOpen Browser Interface",
                                   font=('Arial', 12, 'bold'),
                                   bg='#3b82f6',
                                   fg='white',
                                   command=lambda: self.select_mode('web-only'),
                                   pady=15,
                                   relief='flat',
                                   cursor='hand2')
                web_btn.pack(fill='x', pady=10)
                
                # Exit Button
                exit_btn = tk.Button(buttons_frame,
                                    text="❌ EXIT",
                                    font=('Arial', 10),
                                    bg='#6b7280',
                                    fg='white',
                                    command=self.root.quit,
                                    pady=10,
                                    relief='flat',
                                    cursor='hand2')
                exit_btn.pack(fill='x', pady=(20, 0))
                
                # Bind Escape key to exit
                self.root.bind('<Escape>', lambda e: self.root.quit())
                
            def select_mode(self, mode):
                self.selected_mode = mode
                self.root.quit()
                
            def run(self):
                self.root.mainloop()
                return self.selected_mode
        
        launcher = QuickLauncher()
        return launcher.run()
        
    except Exception as e:
        print(f"⚠️  GUI launcher failed: {e}")
        print("🔄 Falling back to terminal mode...")
        return None

def main():
    """Main startup function with improved error handling"""
    print("🚀 Starting Drsya Security Monitor...")
    
    # Check if we're in a virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✅ Virtual environment detected")
    else:
        print("⚠️  Not in virtual environment - some features may not work")
    
    # Try GUI first, fall back to terminal
    mode = None
    
    if check_gui_available():
        print("🖥️  GUI available - launching graphical mode selector...")
        try:
            mode = launch_gui_mode_selector()
        except Exception as e:
            print(f"⚠️  GUI failed: {e}")
            print("🔄 Falling back to terminal mode...")
    
    # Fall back to terminal mode selection
    if mode is None:
        print("📟 Using terminal mode selector...")
        mode = show_terminal_mode_selection()
    
    # Handle the selected mode
    if mode == "web-only":
        launch_web_dashboard()
        return
    
    # Launch Drsya with selected mode
    monitor_path = Path(__file__).parent / "drsya_monitor.py"
    
    if not monitor_path.exists():
        print(f"❌ Error: {monitor_path} not found!")
        print("📁 Current directory:", Path(__file__).parent)
        print("📋 Available files:")
        for file in Path(__file__).parent.glob("*.py"):
            print(f"   • {file.name}")
        sys.exit(1)
    
    print(f"🚀 Launching Drsya in {mode} mode...")
    print("🌐 Web dashboard will open automatically")
    print("🛑 Press Ctrl+C to stop monitoring")
    print("=" * 50)
    
    try:
        cmd = [sys.executable, str(monitor_path)]
        if mode == "strict":
            cmd.append("--strict")
        else:
            cmd.append("--lenient")
        
        # Start the monitor
        subprocess.run(cmd)
        
    except KeyboardInterrupt:
        print("\n🛑 Drsya stopped by user")
    except Exception as e:
        print(f"❌ Failed to start Drsya: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

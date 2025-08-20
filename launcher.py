#!/usr/bin/env python3
"""
Drsya Security Monitor - Simple Launcher
Mode selection and startup interface
"""

import tkinter as tk
from tkinter import messagebox
import subprocess
import sys
from pathlib import Path

class DrsyaLauncher:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Dṛśya Security Monitor")
        self.root.geometry("500x400")
        self.root.configure(bg='#0a0e16')
        self.root.resizable(False, False)
        
        self.mode_var = tk.StringVar(value="lenient")
        self.setup_ui()
        self.center_window()
        
    def center_window(self):
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - 250
        y = (self.root.winfo_screenheight() // 2) - 200
        self.root.geometry(f"500x400+{x}+{y}")
        
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg='#0a0e16')
        header_frame.pack(pady=40)
        
        title_label = tk.Label(header_frame, 
                              text="Dṛśya", 
                              font=('Arial', 32, 'bold'),
                              fg='#3b82f6', 
                              bg='#0a0e16')
        title_label.pack()
        
        subtitle_label = tk.Label(header_frame, 
                                 text="Security Monitor", 
                                 font=('Arial', 12),
                                 fg='#d1d5db', 
                                 bg='#0a0e16')
        subtitle_label.pack(pady=(5, 20))
        
        # Mode selection
        mode_frame = tk.Frame(self.root, bg='#0a0e16')
        mode_frame.pack(pady=20)
        
        tk.Label(mode_frame, 
                text="Select Monitoring Mode:", 
                font=('Arial', 14, 'bold'),
                fg='#f9fafb', 
                bg='#0a0e16').pack(pady=(0, 20))
        
        # Lenient mode option
        lenient_frame = tk.Frame(mode_frame, bg='#1f2937', relief='solid', bd=1)
        lenient_frame.pack(fill='x', pady=5, padx=40)
        
        tk.Radiobutton(lenient_frame, 
                      text="🛡️ Lenient Mode (Recommended)", 
                      variable=self.mode_var, 
                      value="lenient",
                      font=('Arial', 12, 'bold'),
                      fg='#10b981', 
                      bg='#1f2937',
                      selectcolor='#1f2937',
                      activebackground='#1f2937',
                      activeforeground='#10b981').pack(anchor='w', padx=15, pady=10)
        
        tk.Label(lenient_frame, 
                text="Monitor and report threats only • Safe for daily use",
                font=('Arial', 9),
                fg='#9ca3af', 
                bg='#1f2937').pack(anchor='w', padx=35, pady=(0, 10))
        
        # Strict mode option
        strict_frame = tk.Frame(mode_frame, bg='#1f2937', relief='solid', bd=1)
        strict_frame.pack(fill='x', pady=5, padx=40)
        
        tk.Radiobutton(strict_frame, 
                      text="⚔️ Strict Mode (Advanced)", 
                      variable=self.mode_var, 
                      value="strict",
                      font=('Arial', 12, 'bold'),
                      fg='#ef4444', 
                      bg='#1f2937',
                      selectcolor='#1f2937',
                      activebackground='#1f2937',
                      activeforeground='#ef4444').pack(anchor='w', padx=15, pady=10)
        
        tk.Label(strict_frame, 
                text="Auto-terminate threats • Protection scoring • Advanced features",
                font=('Arial', 9),
                fg='#9ca3af', 
                bg='#1f2937').pack(anchor='w', padx=35, pady=(0, 10))
        
        # Launch button
        launch_btn = tk.Button(self.root, 
                              text="🚀 Launch Drsya", 
                              font=('Arial', 14, 'bold'),
                              bg='#3b82f6', 
                              fg='white',
                              command=self.launch_drsya,
                              padx=40, 
                              pady=12, 
                              border=0,
                              cursor='hand2')
        launch_btn.pack(pady=30)
        
        # Bind Enter key
        self.root.bind('<Return>', lambda e: self.launch_drsya())
        
    def launch_drsya(self):
        mode = self.mode_var.get()
        
        try:
            script_path = Path(__file__).parent / "drsya_monitor.py"
            
            if not script_path.exists():
                raise FileNotFoundError("drsya_monitor.py not found")
            
            cmd = [sys.executable, str(script_path)]
            if mode == "strict":
                cmd.append("--strict")
            else:
                cmd.append("--lenient")
            
            subprocess.Popen(cmd)
            
            messagebox.showinfo("Success", 
                               f"Drsya started in {mode} mode!\n\n"
                               "The web dashboard will open automatically.\n"
                               "You can close this launcher now.")
            
            self.root.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start Drsya:\n{str(e)}")
    
    def run(self):
        self.root.mainloop()

def main():
    app = DrsyaLauncher()
    app.run()

if __name__ == "__main__":
    main()

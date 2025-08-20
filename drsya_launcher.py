#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DRŚYA launcher (headless)

- Creates a Desktop shortcut "DRŚYA.desktop" with your icon:
  /home/nexus/drsya_security_monitor/final icon.jpg
- Shortcut starts the Flask app and opens the dashboard in your browser.
- You can also run this script to start/stop or (re)install the shortcut.

Usage:
  python3 drsya_launcher.py --install-shortcut     # (default) install/refresh .desktop
  python3 drsya_launcher.py --start                 # start server and open browser
  python3 drsya_launcher.py --stop                  # try to stop server
  python3 drsya_launcher.py --host 127.0.0.1 --port 5000 --mode strict
"""

import argparse
import os
import sys
import subprocess
import time
import webbrowser
import json
from pathlib import Path

# ---------- Settings ----------
APP_FILE = "drsya_app.py"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
DEFAULT_MODE = "strict"

ICON_PATH = "/home/nexus/drsya_security_monitor/final icon.jpg"
DESKTOP_FILE_NAME = "DRŚYA.desktop"

def here() -> Path:
    return Path(__file__).resolve().parent

def app_path() -> Path:
    return here() / APP_FILE

def ensure_shortcut(host: str, port: int, mode: str) -> Path:
    desktop_dir = Path.home() / "Desktop"
    desktop_dir.mkdir(parents=True, exist_ok=True)
    dest = desktop_dir / DESKTOP_FILE_NAME

    # Exec uses bash -lc so we can cd to folder and background the server, then open browser.
    exec_cmd = (
        f"/usr/bin/env bash -lc "
        f"\"cd '{here()}' && "
        f"{sys.executable} '{app_path()}' --host {host} --port {port} --mode {mode} >/tmp/drsya.log 2>&1 & "
        f"sleep 1 && xdg-open http://{host}:{port}\""
    )

    desktop_text = f"""[Desktop Entry]
Type=Application
Name=DRŚYA Security Monitor
Comment=Start DRŚYA dashboard
Exec={exec_cmd}
Terminal=false
Icon={ICON_PATH}
Categories=Utility;Security;
"""
    dest.write_text(desktop_text, encoding="utf-8")
    os.chmod(dest, 0o755)
    return dest

def server_alive(host: str, port: int) -> bool:
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=1.6) as r:
            return (getattr(r, "status", 200) == 200)
    except Exception:
        return False

def start_server(host: str, port: int, mode: str):
    if server_alive(host, port):
        return True
    if not app_path().exists():
        print(f"[!] {APP_FILE} not found next to the launcher at {here()}")
        return False
    cmd = [sys.executable, str(app_path()), "--host", host, "--port", str(port), "--mode", mode]
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # wait up to ~3s
    for _ in range(30):
        time.sleep(0.1)
        if server_alive(host, port):
            return True
    return False

def stop_server(host: str, port: int):
    import urllib.request, urllib.error
    try:
        req = urllib.request.Request(f"http://{host}:{port}/stop_monitoring", data=b"{}", headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=1.5)
    except Exception:
        pass

def main():
    p = argparse.ArgumentParser(description="DRŚYA launcher")
    p.add_argument("--install-shortcut", action="store_true", help="Install/refresh Desktop shortcut (default)")
    p.add_argument("--start", action="store_true", help="Start server and open dashboard")
    p.add_argument("--stop", action="store_true", help="Attempt to stop server")
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--mode", choices=["strict","lenient"], default=DEFAULT_MODE)
    args = p.parse_args()

    # default action if none provided
    if not (args.install_shortcut or args.start or args.stop):
        args.install_shortcut = True

    if args.install_shortcut:
        path = ensure_shortcut(args.host, args.port, args.mode)
        print(f"[+] Installed desktop shortcut: {path}")
        return

    if args.start:
        ok = start_server(args.host, args.port, args.mode)
        if not ok:
            print("[!] Server failed health check. See /tmp/drsya.log if run via shortcut.")
            sys.exit(1)
        webbrowser.open(f"http://{args.host}:{args.port}")
        print(f"[+] Dashboard opened at http://{args.host}:{args.port}")
        return

    if args.stop:
        stop_server(args.host, args.port)
        print("[*] Stop signal sent (best effort).")
        return

if __name__ == "__main__":
    main()


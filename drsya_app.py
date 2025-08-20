#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import psutil
import time
import argparse
import os
import threading
import json
import getpass
import re
import zipfile
import signal
from datetime import datetime
from html import escape as html_escape
from flask import Flask, render_template_string, request, jsonify, send_file, abort
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import requests

# ---------------- App & Socket ----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'drsya_security_monitor_key_2024'
app.config['TEMPLATES_AUTO_RELOAD'] = True
CORS(app, allow_headers=["Content-Type"], origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ---------------- Config persistence ----------------
CONFIG_PATH = os.path.join(os.getcwd(), "config.json")

def load_config_from_disk():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config_to_disk(conf: dict):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(conf, f, indent=2, sort_keys=True)
    except Exception:
        pass

# ---------------- Globals ----------------
monitoring_active = False
monitoring_thread = None
current_mode = 'strict'        # 'strict' | 'lenient'
system_start_time = time.time()
activity_log = []
safe_text_entered = False

# Threat state
threat_state = {
    'high': 0, 'medium': 0, 'low': 0,
    'neutralized': 0, 'total': 0,
    'processes': [], 'last_scan': None,
    'is_active': False, 'safe_processes': 0,
    'total_scanned': 0, 'scan_time': 0.0, 'uptime': 0
}

# Config (defaults, then overlay)
config_defaults = {
    'auto_kill_high': False,
    'refresh_rate': 5,
    'theme': 'dark',
    'notifications': True,
    'whitelist': [
        'chrome','firefox','explorer','system','python3','python','code','systemd','gnome',
        'kworker','xorg','wayland','dbus','pulseaudio','pipewire','bluetoothd','NetworkManager'
    ],
    'logo_path': "/home/nexus/drsya_security_monitor/final icon.jpg",
    'manual_path': "/home/nexus/drsya_security_monitor/User Manual.docx",
    'denylist': [],
    'powerbi_url': os.environ.get('DRSYA_POWERBI_URL', ''),
    'powerbi_auto': False,
    'powerbi_spaced_fields': False,
    'background_path': "/mnt/data/e0873954-1155-4fbd-a7df-34081a9c8aff.jpg",  # circuit wallpaper
}
config = {**config_defaults, **load_config_from_disk()}

# ---------- Rules ----------
SUSPICIOUS_KEYWORDS = {
    "Keylogger": {"keywords": ["keylog","keylogger","intercept","keystroke","keyhook","keyboard"], "priority": "High"},
    "Mic Access": {"keywords": ["mic","microphone","audio","pulse","alsa","arecord","pactl","parec"], "priority": "Medium"},
    "Bluetooth Access": {"keywords": ["bluetoothd","btmon","bluetooth","bluez"], "priority": "Medium"},
    "Camera Access": {"keywords": ["v4l","webcam","camera","cheese","ffmpeg","obs"], "priority": "Medium"},
    "Screen Monitor": {"keywords": ["xinput","xev","screenlog","record","screencap","xwd"], "priority": "Medium"},
    "Backdoor/RAT": {"keywords": ["rat","backdoor","darkcomet","njrat","netwire","cybergate","reverse"], "priority": "High"}
}
PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

INTEL_RULES = [
    {
        "match_any": ["keylog","xinput","xev"],
        "mitre": [{"id": "T1056", "name": "Input Capture (Keylogging)"}],
        "behavior": ["Reads /dev/input*", "Hooks keyboard events"],
        "cve_hints": [{"id": "CVE-2021-0000", "cvss": 7.5, "hint": "Generic privilege issue"}],
        "compliance": ["Possible PII violation", "Policy: INPUT-01"]
    },
    {
        "match_any": ["arecord","pactl","parec","pulse","alsa"],
        "mitre": [{"id": "T1123", "name": "Audio Capture"}],
        "behavior": ["Accesses /dev/snd*", "Mic stream active"],
        "cve_hints": [{"id": "CVE-2020-0000", "cvss": 6.8, "hint": "Audio stack exposure"}],
        "compliance": ["Consent required for audio", "Policy: MIC-01"]
    },
    {
        "match_any": ["ffmpeg","obs","v4l","webcam","camera","cheese"],
        "mitre": [{"id": "T1125", "name": "Video Capture"}],
        "behavior": ["Accesses /dev/video*", "High frame IO"],
        "cve_hints": [{"id": "CVE-2019-0000", "cvss": 7.0, "hint": "Video subsystem info leak"}],
        "compliance": ["Camera access logging", "Policy: CAM-01"]
    },
    {
        "match_any": ["bluetoothd","btmon","bluez"],
        "mitre": [{"id": "T1040", "name": "Network Sniffing (Proximity)"}],
        "behavior": ["Controls BT stack", "Device discovery"],
        "cve_hints": [{"id": "CVE-2020-0022", "cvss": 8.8, "hint": "BlueFrag class"}],
        "compliance": ["Wireless policy check", "Policy: BT-01"]
    },
    {
        "match_any": ["rat","backdoor","netcat","bash -i","reverse"],
        "mitre": [{"id": "T1219", "name": "Remote Access Tools"}],
        "behavior": ["Outbound C2", "Hidden listener / reverse shell"],
        "cve_hints": [{"id": "CVE-2018-0000", "cvss": 8.0, "hint": "Remote-control abuse"}],
        "compliance": ["Unauthorized remote admin", "Enforce MFA/allowlist"]
    }
]

# ---------- Embedded Docs (fallback) ----------
EMBEDDED_MANUAL = """
*System Overview*
DRŚYA monitors in real-time for keylogging, microphone, camera, Bluetooth, and suspicious network use.

*Process ID (PID) Analysis*
Each detected process includes PID, type, priority, and resource access for investigation.

*Access Column*
Keyboard / Microphone / Camera / Bluetooth / Network / Yes indicate the resource in use.

*Modes*
Strict: configurable refresh, auto-kill (optional), Intel & Summary enabled.
Lenient: light scanning, basic UI only.

*Protect*
Suspends the process now and adds it to a prevention list so next time it’s auto-suspended and downgraded.

*Whitelist*
Add trusted process names (one per line) to avoid false positives.

*Power BI*
Set a streaming URL to push summary rows of the latest detections.
"""

EMBEDDED_FAQ = """
*What types of threats does the system detect?*
The system is designed to identify and flag keylogging attempts, unauthorized access to sensors (microphone, camera, Bluetooth), and other suspicious processes attempting to interact with sensitive resources.

*How does the system differentiate between legitimate and malicious processes?*
The detection engine uses process behaviour analysis, resource access patterns, and user-defined whitelists to distinguish between trusted applications and potential threats.

*Will the system slow down my computer?*
No, the system is designed for minimal performance impact. Lenient Mode runs lightweight scans every 10 seconds, while Strict Mode allows custom intervals to balance performance and security needs.

*Can I customize which processes are flagged?*
Yes, the Whitelist Management feature allows you to mark specific applications as trusted, ensuring they are not flagged in future scans.

*How frequently does the system scan for threats?*
• Lenient Mode scans every 10 seconds.
• Strict Mode has configurable scan intervals that can be adjusted for higher responsiveness or lower system impact.

*Does the system automatically remove threats?*
• In Strict Mode, confirmed high-risk processes are terminated automatically via the Auto-Kill feature. In Lenient Mode, termination requires manual user approval.

*What happens if I accidentally whitelist a malicious process?*
• You can easily remove a process from the whitelist at any time. The system will resume monitoring it in subsequent scans.
"""

# ---------- Helpers ----------
def build_intel_for(name: str, cmd: str):
    lname = (name or "").lower()
    lcmd = (cmd or "").lower()
    pack = {"cve": [], "mitre": [], "behavior": [], "compliance": []}
    for rule in INTEL_RULES:
        if any(k in lname or k in lcmd for k in rule["match_any"]):
            pack["cve"].extend(rule["cve_hints"])
            pack["mitre"].extend(rule["mitre"])
            pack["behavior"].extend(rule["behavior"])
            pack["compliance"].extend(rule["compliance"])
    seen = set(); beh=[]
    for b in pack["behavior"]:
        if b not in seen: beh.append(b); seen.add(b)
    pack["behavior"] = beh
    return pack

def recommendations_for(ptype: str, name: str):
    base = [
        "Verify binary path & signature (which/stat/sha256sum).",
        "If legit, add to Whitelist from Configuration.",
        "If unknown, use Protect to suspend now and auto-suspend next time.",
        "Keep OS & packages updated."
    ]
    extra = []
    p = (ptype or "").lower()
    if "keylog" in p:
        extra = ["Check /dev/input usage: sudo lsof /dev/input/event*", "Audit crontab/systemd for persistence"]
    elif "mic" in p:
        extra = ["Mute mic: pactl set-source-mute @DEFAULT_SOURCE@ 1", "Close apps using PulseAudio/ALSA"]
    elif "camera" in p or "video" in p:
        extra = ["List /dev/video users: sudo lsof /dev/video*", "Disable virtual camera modules if unused"]
    elif "bluetooth" in p:
        extra = ["Turn off Bluetooth if unused", "Remove unknown paired devices"]
    elif "remote access" in p or "rat" in p or "backdoor" in p:
        extra = ["Disconnect network & rotate passwords", "Check user/system autoruns"]
    return base + extra

def linux_sensor_heuristics(proc: psutil.Process):
    access = "No"; ptype=None; priority=None
    try:
        for f in proc.open_files() or []:
            path = f.path.lower()
            if path.startswith("/dev/input"): ptype,priority,access="Keylogger","High","Keyboard"; break
            if path.startswith("/dev/video"): ptype,priority,access="Camera Access","Medium","Camera"; break
            if path.startswith("/dev/snd"):   ptype,priority,access="Mic Access","Medium","Microphone"; break
        if not ptype:
            for c in proc.net_connections(kind='inet'):
                if c.laddr and c.raddr and c.status == psutil.CONN_ESTABLISHED:
                    ptype,priority,access="Network Activity","Low","Network"; break
        if not ptype:
            cl = " ".join(proc.cmdline() or []).lower()
            if "bluetooth" in cl or "bluez" in cl:
                ptype,priority,access="Bluetooth Access","Medium","Bluetooth"
    except (psutil.AccessDenied, psutil.NoSuchProcess, ProcessLookupError):
        pass
    except Exception:
        pass
    return ptype, priority, access

def classify_process_keywords(name, cmdline):
    full_cmd = " ".join(cmdline).lower()
    lname = (name or "").lower()
    for ptype, meta in SUSPICIOUS_KEYWORDS.items():
        for kw in meta["keywords"]:
            if kw in lname or kw in full_cmd:
                access = "Keyboard" if "key" in ptype.lower() else ("Microphone" if "mic" in ptype.lower()
                          else ("Camera" if "camera" in ptype.lower() else ("Bluetooth" if "bluetooth" in ptype.lower() else "Yes")))
                return ptype, meta["priority"], access
    return None, None, "No"

def is_whitelisted(name):
    lname = (name or "").lower()
    return any(w.lower() in lname for w in config.get('whitelist', []))

def is_denied(name):
    lname = (name or "").lower()
    return any(d.lower() in lname for d in config.get('denylist', []))

def log_activity(kind, message):
    activity_log.append({'type': kind, 'message': message,
                         'timestamp': datetime.now().isoformat(),
                         'time_display': datetime.now().strftime('%H:%M:%S')})
    if len(activity_log) > 120: del activity_log[:60]

# --------- Robust kill ----------
def kill_process_enhanced(pid: int):
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        try:
            proc.suspend()
        except Exception:
            pass
        try:
            children = proc.children(recursive=True)
            for ch in children:
                try:
                    ch.suspend()
                    ch.terminate()
                except Exception:
                    pass
            psutil.wait_procs(children, timeout=2)
        except Exception:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=3)
            if not proc.is_running():
                return True, f"Process {name} (PID {pid}) terminated gracefully"
        except psutil.TimeoutExpired:
            pass
        except psutil.NoSuchProcess:
            return True, f"Process {name} (PID {pid}) already terminated"
        try:
            proc.kill()
            proc.wait(timeout=2)
            if not proc.is_running():
                return True, f"Process {name} (PID {pid}) force killed"
        except psutil.TimeoutExpired:
            pass
        except psutil.NoSuchProcess:
            return True, f"Process {name} (PID {pid}) already terminated"
        try:
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)
            try:
                psutil.Process(pid)
                return False, f"Process {name} (PID {pid}) resisted termination — run with sudo for elevated control"
            except psutil.NoSuchProcess:
                return True, f"Process {name} (PID {pid}) killed via SIGKILL"
        except (OSError, ProcessLookupError):
            return True, f"Process {name} (PID {pid}) terminated"
    except psutil.NoSuchProcess:
        return True, f"Process (PID {pid}) not found — already terminated"
    except psutil.AccessDenied:
        return False, f"Access denied — insufficient privileges to kill PID {pid}. Try running the server with sudo."
    except Exception as e:
        return False, f"Unexpected error killing PID {pid}: {str(e)}"

# --------- Protect / Prevention ----------
def restore_quarantine_process(pid: int):
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        try:
            proc.suspend()
        except psutil.AccessDenied:
            return False, f"Access denied — cannot suspend {name} (PID {pid}). Try running as sudo."
        except Exception as e:
            log_activity('error', f"Restore suspend error: {e}")
        dn = config.get('denylist', [])
        if name not in dn:
            dn.append(name)
            config['denylist'] = dn
            save_config_to_disk(config)
        return True, f"Process {name} (PID {pid}) suspended and added to prevention list"
    except psutil.NoSuchProcess:
        return True, f"Process (PID {pid}) not found — may have exited already"
    except Exception as e:
        return False, f"Unexpected restore error: {str(e)}"

# ---------------- Core scan ----------------
def scan_once():
    start = time.time()
    totals = {'High':0,'Medium':0,'Low':0}
    processes=[]; safe=0; total=0
    for proc in psutil.process_iter(['pid','name','cmdline','status','cpu_percent','memory_percent','create_time']):
        try:
            info = proc.info; total += 1
            name = info.get('name') or ''; cmd = info.get('cmdline') or []
            if is_whitelisted(name) or info.get('status') == 'zombie':
                safe += 1; continue
            ptype, priority, access = classify_process_keywords(name, cmd)
            if not ptype:
                hp,pr,acc = linux_sensor_heuristics(proc)
                if hp: ptype,priority,access = hp,pr,acc
            if ptype:
                restored = False
                if is_denied(name):
                    try:
                        proc.suspend()
                        restored = True
                    except Exception:
                        pass
                item = {
                    'PID': info['pid'],
                    'Name': name,
                    'Type': ptype + (' (Protected)' if restored else ''),
                    'Priority': ('Low' if restored else (priority or 'Low')),
                    'Access': ('Suspended' if restored else access),
                    'CPU': round(info.get('cpu_percent') or 0.0, 1),
                    'Memory': round(info.get('memory_percent') or 0.0, 1),
                    'Created': datetime.fromtimestamp(info['create_time']).strftime('%H:%M:%S') if info.get('create_time') else '-',
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                }
                intel = build_intel_for(item['Name'], " ".join(cmd))
                item['Intel'] = intel
                item['Recs'] = recommendations_for(ptype, name)
                processes.append(item)
                totals[item['Priority']] = totals.get(item['Priority'], 0) + 1

                if current_mode == 'strict' and config.get('auto_kill_high') and (priority or '')=='High' and not restored:
                    ok, msg = kill_process_enhanced(info['pid'])
                    if ok: threat_state['neutralized'] += 1
                    log_activity('kill' if ok else 'error', f"Auto-kill {'OK' if ok else 'failed'}: {msg}")
            else:
                safe += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            log_activity('error', f"scan error: {e}")
    processes.sort(key=lambda x:(PRIORITY_ORDER.get(x['Priority'],3), -x['CPU'], -x['Memory']))
    elapsed = round(time.time()-start, 2)
    threat_state.update({
        'high': totals['High'], 'medium': totals['Medium'], 'low': totals['Low'],
        'total': totals['High']+totals['Medium']+totals['Low'],
        'processes': processes, 'last_scan': datetime.now(),
        'safe_processes': safe, 'total_scanned': total,
        'scan_time': elapsed, 'uptime': round(time.time()-system_start_time, 0)
    })
    log_activity('scan', f"Scan complete: {threat_state['total']} threats in {elapsed}s")
    return threat_state

def monitoring_loop():
    log_activity('system', f"Monitoring started in {current_mode} mode")
    while monitoring_active:
        data = scan_once()
        acc = {}
        for r in data['processes'][:20]:
            key = r.get('Access','Other') or 'Other'
            acc[key] = acc.get(key,0)+1
        socketio.emit('threat_update', {
            'threats': data['processes'],
            'summary': {
                'high': data['high'], 'medium': data['medium'],
                'low': data['low'], 'total': data['total'],
                'neutralized': data['neutralized'],
                'safe_processes': data['safe_processes'],
                'total_scanned': data['total_scanned']
            },
            'status': {
                'last_scan': data['last_scan'].strftime('%H:%M:%S') if data['last_scan'] else '-',
                'uptime': data['uptime'], 'mode': current_mode,
                'scan_time': data.get('scan_time', 0)
            },
            'access_counts': acc,
            'activity': activity_log[-12:], 'timestamp': datetime.now().isoformat()
        })
        time.sleep(config.get('refresh_rate',5) if current_mode=='strict' else 10)

# ---------------- Power BI helpers ----------------
def build_powerbi_payload():
    now = datetime.utcnow().isoformat() + "Z"
    top = threat_state.get('processes', [])[:10]
    access_counts = {}
    for r in top:
        k = r.get('Access','Other') or 'Other'
        access_counts[k] = access_counts.get(k, 0) + 1

    if not config.get('powerbi_spaced_fields'):
        row = {
            "ts": now,
            "high": int(threat_state.get('high',0)),
            "medium": int(threat_state.get('medium',0)),
            "low": int(threat_state.get('low',0)),
            "total": int(threat_state.get('total',0)),
            "safe": int(threat_state.get('safe_processes',0)),
            "neutralized": int(threat_state.get('neutralized',0)),
            "scan_time": float(threat_state.get('scan_time',0.0)),
            "mode": current_mode,
            "top_names": ",".join([p.get('Name','') for p in top]),
            "top_types": ",".join([p.get('Type','') for p in top]),
            "access_breakdown": json.dumps(access_counts),
        }
    else:
        row = {
            "ts ": now,
            "high": int(threat_state.get('high',0)),
            "medium": int(threat_state.get('medium',0)),
            "low": int(threat_state.get('low',0)),
            "total": int(threat_state.get('total',0)),
            "safe": int(threat_state.get('safe_processes',0)),
            "neutralized": int(threat_state.get('neutralized',0)),
            "scan time": float(threat_state.get('scan_time',0.0)),
            "mode": current_mode,
            "top names": ",".join([p.get('Name','') for p in top]),
            "top types": ",".join([p.get('Type','') for p in top]),
            "access breakdown": json.dumps(access_counts),
        }
    return [row]

def push_to_powerbi_once():
    url = (config.get('powerbi_url') or '').strip()
    if not url:
        log_activity('error', 'Power BI URL not set (Configuration → Power BI Streaming)')
        return {'ok': False, 'message': 'Power BI URL not set'}
    try:
        payload = build_powerbi_payload()
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code in (200, 202):
            log_activity('system', 'Pushed current data to Power BI')
            return {'ok': True}
        log_activity('error', f'Power BI push failed: {r.status_code} {r.text[:160]}')
        return {'ok': False, 'message': f'{r.status_code} {r.text}'}
    except Exception as e:
        log_activity('error', f'Power BI push error: {e}')
        return {'ok': False, 'message': str(e)}

powerbi_auto_thread = None
powerbi_auto_running = False

def powerbi_auto_loop():
    global powerbi_auto_running
    powerbi_auto_running = True
    log_activity('system', 'Power BI auto-stream ON (30s)')
    while powerbi_auto_running:
        try:
            push_to_powerbi_once()
        except Exception as e:
            log_activity('error', f'Power BI auto push error: {e}')
        for _ in range(30):
            if not powerbi_auto_running: break
            time.sleep(1)
    log_activity('system', 'Power BI auto-stream OFF')

# ---------------- API ----------------
@app.route('/health')
def health(): return "ok", 200

@app.route('/api/status')
def api_status():
    return jsonify({'success': True, 'data': {
        'monitoring_active': monitoring_active, 'mode': current_mode,
        'uptime': round(time.time()-system_start_time,1),
        'threats_neutralized': threat_state['neutralized'], 'config': config,
        'last_scan': threat_state['last_scan'].isoformat() if threat_state['last_scan'] else None
    }})

@app.route('/api/threats')
def api_threats():
    return jsonify({'success': True, 'timestamp': datetime.now().isoformat(), 'data': {
        'summary': {'high': threat_state['high'],'medium': threat_state['medium'],
                    'low': threat_state['low'],'total': threat_state['total'],
                    'neutralized': threat_state['neutralized'], 'safe_processes': threat_state['safe_processes'],
                    'total_scanned': threat_state['total_scanned']},
        'details': threat_state['processes'][:20],
        'status': {'active': monitoring_active, 'mode': current_mode,
                   'last_scan': threat_state['last_scan'].isoformat() if threat_state['last_scan'] else None,
                   'uptime': threat_state['uptime'], 'scan_time': threat_state['scan_time']}
    }})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = scan_once()
    safe_copy = dict(data)
    if isinstance(safe_copy.get('last_scan'), datetime):
        safe_copy['last_scan'] = safe_copy['last_scan'].isoformat()
    return jsonify({'success': True, 'data': safe_copy})

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    global monitoring_active, monitoring_thread, system_start_time
    if not monitoring_active:
        monitoring_active=True; threat_state['is_active']=True; system_start_time=time.time()
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True); monitoring_thread.start()
        return jsonify({'status':'started','mode':current_mode})
    return jsonify({'status':'already_running','mode':current_mode})

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    global monitoring_active
    monitoring_active=False; threat_state['is_active']=False; log_activity('system',"Monitoring stopped")
    return jsonify({'status':'stopped'})

@app.route('/switch_mode', methods=['POST'])
def switch_mode():
    global current_mode
    try:
        data = request.get_json(force=True)
        new_mode = data.get('mode')
        if new_mode in ('lenient','strict'):
            current_mode=new_mode; log_activity('system', f"Switched to {new_mode} mode")
            return jsonify({'status':'success','mode':new_mode})
        return jsonify({'status':'error','message':'Invalid mode'})
    except Exception as e:
        return jsonify({'status':'error','message':str(e)})

@app.route('/update_config', methods=['POST'])
def update_config():
    try:
        data = request.get_json(force=True)
        allowed={'auto_kill_high','refresh_rate','theme','notifications','whitelist',
                 'powerbi_url','powerbi_auto','powerbi_spaced_fields','denylist','manual_path','background_path'}
        for k in list(data.keys()):
            if k not in allowed: data.pop(k)

        if 'whitelist' in data and isinstance(data['whitelist'], str):
            wl=[w.strip() for w in data['whitelist'].replace(',', '\n').splitlines() if w.strip()]
            data['whitelist']=wl
        if 'denylist' in data and isinstance(data['denylist'], str):
            dl=[w.strip() for w in data['denylist'].replace(',', '\n').splitlines() if w.strip()]
            data['denylist']=dl

        if 'powerbi_auto' in data: data['powerbi_auto'] = bool(data['powerbi_auto'])
        if 'powerbi_spaced_fields' in data: data['powerbi_spaced_fields'] = bool(data['powerbi_spaced_fields'])

        if 'refresh_rate' in data:
            try:
                data['refresh_rate'] = max(1, int(data['refresh_rate']))
            except Exception:
                data['refresh_rate'] = config.get('refresh_rate', 5)

        config.update(data)
        save_config_to_disk(config)
        log_activity('config',"Configuration updated")
        return jsonify({'status':'success','config':config})
    except Exception as e:
        return jsonify({'status':'error','message':str(e)})

@app.route('/kill_process', methods=['POST'])
def kill_process():
    try:
        data=request.get_json(force=True); pid=int(data.get('pid'))
        success, message = kill_process_enhanced(pid)
        if success:
            threat_state['neutralized']+=1
            log_activity('kill', message)
            return jsonify({'status':'killed','message':message})
        else:
            log_activity('error', message)
            return jsonify({'status':'error','message':message})
    except ValueError:
        return jsonify({'status':'error','message':'Invalid PID'})
    except Exception as e:
        return jsonify({'status':'error','message':str(e)})

@app.route('/restore_process', methods=['POST'])
def restore_process():
    try:
        data=request.get_json(force=True); pid=int(data.get('pid'))
        success, message = restore_quarantine_process(pid)
        if success:
            log_activity('restore', message)
            return jsonify({'status':'restored','message':message,'denylist':config.get('denylist',[])})
        else:
            log_activity('error', message)
            return jsonify({'status':'error','message':message})
    except ValueError:
        return jsonify({'status':'error','message':'Invalid PID'})
    except Exception as e:
        return jsonify({'status':'error','message':str(e)})

@app.route('/set_logo', methods=['POST'])
def set_logo():
    try:
        path = request.get_json(force=True).get('path')
        if not path or not os.path.exists(path):
            return jsonify({'status':'error','message':'Path missing or not found'})
        config['logo_path'] = path
        save_config_to_disk(config)
        return jsonify({'status':'ok','path': path})
    except Exception as e:
        return jsonify({'status':'error','message':str(e)})

@app.route('/logo')
def logo():
    cand = [config.get('logo_path'),
            os.environ.get('DRSYA_LOGO'),
            '/mnt/data/logo.png']
    for p in cand:
        if p and os.path.exists(p):
            mt = 'image/jpeg' if p.lower().endswith(('.jpg','.jpeg')) else 'image/png'
            return send_file(p, mimetype=mt, conditional=True)
    abort(404)

@app.route('/background')
def background():
    cand = [config.get('background_path')]
    for p in cand:
        if p and os.path.exists(p):
            return send_file(p, mimetype='image/jpeg', conditional=True)
    abort(404)

@app.route('/push_powerbi', methods=['POST'])
def api_push_powerbi():
    res = push_to_powerbi_once()
    return jsonify({'success': res.get('ok', False), 'message': res.get('message','')})

@app.route('/powerbi_auto', methods=['POST'])
def api_powerbi_auto():
    global powerbi_auto_thread, powerbi_auto_running
    data = request.get_json(force=True)
    enable = bool(data.get('enable', False))
    url = (data.get('url') or '').strip()
    if url:
        config['powerbi_url'] = url
        save_config_to_disk(config)
        log_activity('config', 'Power BI URL updated via UI')

    if 'spaced_fields' in data:
        config['powerbi_spaced_fields'] = bool(data.get('spaced_fields'))
        save_config_to_disk(config)

    if enable and not powerbi_auto_running:
        powerbi_auto_thread = threading.Thread(target=powerbi_auto_loop, daemon=True)
        powerbi_auto_thread.start()
        config['powerbi_auto'] = True
        save_config_to_disk(config)
        return jsonify({'success': True, 'status': 'on'})
    if not enable and powerbi_auto_running:
        powerbi_auto_running = False
        config['powerbi_auto'] = False
        save_config_to_disk(config)
        return jsonify({'success': True, 'status': 'off'})
    return jsonify({'success': True, 'status': 'on' if powerbi_auto_running else 'off'})

# ---------------- Docs rendering ----------------
def load_textfile_safe(path):
    try:
        with open(path, 'rb') as f: blob = f.read()
        for enc in ('utf-8','utf-16','latin-1'):
            try: return blob.decode(enc)
            except Exception: continue
        return blob.decode('utf-8','replace')
    except Exception:
        return ""

def load_docx_text(path):
    try:
        with zipfile.ZipFile(path) as z:
            xml = z.read('word/document.xml').decode('utf-8', 'ignore')
        xml = re.sub(r'</w:p>', '\n\n', xml)
        text = re.sub(r'<[^>]+>', '', xml)
        text = re.sub(r'\n{3,}', '\n\n', text).strip()
        return text
    except Exception:
        return ""

def _to_accordion_or_prose(raw_text: str) -> str:
    if not raw_text:
        return '<div class="doc-empty">No content found.</div>'
    safe = html_escape(raw_text.strip())
    lines = [l.rstrip() for l in safe.splitlines()]
    blocks = []
    i = 0
    while i < len(lines):
        if re.fullmatch(r'\*.+\*', lines[i]):
            title = re.sub(r'^\*(.+)\*$', r'\1', lines[i]).strip()
            i += 1
            body_lines = []
            while i < len(lines) and not re.fullmatch(r'\*.+\*', lines[i]):
                body_lines.append(lines[i]); i += 1
            body = "<br>".join(body_lines).replace("<br><br>", "<br><br>")
            blocks.append((title, body))
        else:
            i += 1
    if not blocks:
        paras = [p.strip() for p in safe.split("\n\n") if p.strip()]
        return "<div class='doc-prose'>" + "".join(f"<p>{p}</p>" for p in paras) + "</div>"
    out = ['<div class="doc-accordion">']
    for t, b in blocks:
        out.append(
            f"<details class='doc-item'><summary class='doc-q'>{t}</summary><div class='doc-a'>{b}</div></details>"
        )
    out.append("</div>")
    return "".join(out)

def render_manual_html(raw_text: str) -> str:
    return _to_accordion_or_prose(raw_text)

def render_faq_html(raw_text: str) -> str:
    return _to_accordion_or_prose(raw_text)

# ---------------- HTML ----------------
def html_page(manual_html: str, faq_html: str):
    return r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DRŚYA Security Monitor</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
 --bg-primary:#0b0b0b;--bg-secondary:rgba(18,18,18,.92);--bg-tertiary:rgba(28,28,28,.92);--bg-card:rgba(20,20,20,.92);
 --text-primary:#eaf1f7;--text-secondary:#a7b4c6;--text-muted:#8892a0;
 --accent-blue:#66cfff;--accent-green:#3ddc97;--accent-red:#ff6b6b;--accent-orange:#f6b24a;--accent-purple:#a6a6ff;
 --border-color:#2d2d2d;--shadow:0 8px 24px rgba(0,0,0,.4)
}
body{background:var(--bg-primary);color:var(--text-primary);font-family:'JetBrains Mono',monospace;line-height:1.65;position:relative;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;background:
  url('/background') center/cover no-repeat;opacity:.16;filter:contrast(110%) brightness(95%);pointer-events:none;z-index:-2}
body::after{content:"";position:fixed;inset:0;background:
  radial-gradient(1200px 1200px at 75% 25%, rgba(102,207,255,.06), rgba(0,0,0,0)),
  url('/logo') 90% 8%/420px auto no-repeat;opacity:.10;mix-blend-mode:soft-light;pointer-events:none;z-index:-1}
.container{display:flex;min-height:100vh}
.sidebar{width:300px;background:var(--bg-secondary);backdrop-filter: blur(6px); border-right:1px solid var(--border-color);
  display:flex;flex-direction:column;position:fixed;height:100vh;overflow-y:auto;z-index:900}
.sidebar-header{padding:20px;border-bottom:1px solid var(--border-color);display:flex;align-items:center;gap:12px}
.logo{width:46px;height:46px;border-radius:8px;object-fit:contain;background:#0e0e0e;border:1px solid var(--border-color)}
.brand-block{display:flex;flex-direction:column}
.brand-title{font-size:20px;font-weight:900;letter-spacing:2px;margin-bottom:2px}
.brand-subtitle{font-size:10px;opacity:.85;letter-spacing:1px}
.nav-menu{padding:18px 0;flex:1}
.nav-item{margin:2px 0}
.nav-link{display:flex;align-items:center;padding:10px 18px;color:var(--text-secondary);text-decoration:none;font-size:12px;font-weight:800;cursor:pointer;transition:all .2s;border-left:3px solid transparent}
.nav-link:hover{background:var(--bg-tertiary);color:var(--text-primary);border-left-color:var(--accent-blue)}
.nav-link.active{background:var(--bg-tertiary);color:var(--accent-blue);border-left-color:var(--accent-blue)}
.nav-icon{margin-right:12px;width:18px;height:18px;display:inline-flex}
.mode-controls{padding:16px;border-top:1px solid var(--border-color);background:var(--bg-card)}
.section-label{font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}
.bottom-toggle{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.switch-rail{position:relative;width:88px;height:30px;border-radius:18px;border:1px solid var(--border-color);
  background:linear-gradient(180deg,rgba(36,36,36,.9),rgba(24,24,24,.9)); cursor:pointer}
.switch-knob{position:absolute;top:2px;left:2px;width:26px;height:26px;border-radius:50%;background:#3ddc97;transition:all .25s ease}
.switch-rail.strict .switch-knob{left:60px;background:#ff6b6b}
.main-content{flex:1;margin-left:300px}
.header{background:var(--bg-secondary);backdrop-filter: blur(6px); border-bottom:1px solid var(--border-color);
  padding:16px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:950}
.header-left h1{font-size:20px;font-weight:900;letter-spacing:.5px;background:linear-gradient(135deg,#66cfff 0%,#a6a6ff 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:2px}
.header-left p{color:var(--text-secondary);font-size:11px;font-weight:800}
.status-badge{padding:6px 12px;border-radius:20px;font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.5px;display:flex;align-items:center;gap:6px}
.status-active{background:rgba(61,220,151,.14);color:#3ddc97;border:1px solid rgba(61,220,151,.35)}
.status-inactive{background:rgba(255,107,107,.14);color:#ff6b6b;border:1px solid rgba(255,107,107,.35)}
.status-dot{width:6px;height:6px;border-radius:50%;background:currentColor;animation:pulse 2s infinite}
.page{display:none}.page.active{display:block}
.maxw{max-width:1000px;margin:0 auto}
.dashboard-content{padding:24px}
.control-section{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:12px;padding:16px;margin-bottom:24px;box-shadow:var(--shadow)}
.control-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.control-title{font-size:13px;font-weight:900;color:var(--text-primary)}
.control-buttons{display:flex;gap:10px}
.btn{padding:8px 14px;border:none;border-radius:8px;cursor:pointer;font-size:11px;font-weight:900;letter-spacing:.3px;transition:all .2s;font-family:inherit}
.btn-start{background:linear-gradient(135deg,#3ddc97,#26c383);color:#06121f}
.btn-stop{background:linear-gradient(135deg,#ff6b6b,#e94958);color:#fff}
.btn-intel{background:linear-gradient(135deg,#66cfff,#87d9ff);color:#06121f}
.btn-protect{background:linear-gradient(135deg,#f6b24a,#ffd084);color:#06121f}
.btn-export{background:linear-gradient(135deg,#66cfff,#a6a6ff);color:#06121f}
.btn:hover{transform:translateY(-1px);box-shadow:var(--shadow)}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none}
.metrics-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.metric-card{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:12px;padding:18px;text-align:center;box-shadow:var(--shadow);position:relative;overflow:hidden}
.metric-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(135deg,#66cfff,#a6a6ff)}
.metric-number{font-size:24px;font-weight:900;margin-bottom:6px}
.metric-label{font-size:10px;font-weight:800;text-transform:uppercase;color:var(--text-secondary);letter-spacing:1px}
.metric-total{color:#66cfff}.metric-high{color:#ff6b6b}.metric-medium{color:#f6b24a}.metric-low{color:#3ddc97}
.threats-section{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:12px;box-shadow:var(--shadow);overflow:hidden;margin-bottom:24px}
.threats-header{padding:14px 18px;border-bottom:1px solid var(--border-color);background:var(--bg-card);display:flex;justify-content:space-between;align-items:center}
.threats-title{font-size:13px;font-weight:900;color:var(--text-primary)}
.threats-table{width:100%;border-collapse:collapse}
.threats-table th{background:var(--bg-tertiary);padding:12px 16px;text-align:left;font-size:10px;font-weight:900;text-transform:uppercase;color:var(--text-secondary);letter-spacing:.5px}
.threats-table td{padding:12px 16px;border-bottom:1px solid var(--border-color);font-size:12px}
.threats-table tr:hover{background:var(--bg-card)}
.priority-badge{padding:4px 8px;border-radius:12px;font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.5px}
.priority-high{background:rgba(255,107,107,.12);color:#ff6b6b;border:1px solid rgba(255,107,107,.35)}
.priority-medium{background:rgba(246,178,74,.12);color:#f6b24a;border:1px solid rgba(246,178,74,.35)}
.priority-low{background:rgba(61,220,151,.12);color:#3ddc97;border:1px solid rgba(61,220,151,.35)}
.action-btn{padding:6px 10px;border:none;border-radius:8px;cursor:pointer;font-size:10px;font-weight:900;text-transform:uppercase;margin-right:6px;transition:all .2s;letter-spacing:.5px}
.no-threats{padding:40px;text-align:center;color:var(--text-muted);font-style:italic;font-size:12px}
.activity-feed{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:12px;padding:16px;box-shadow:var(--shadow);height:300px;overflow-y:auto}
.activity-title{font-size:12px;font-weight:900;margin-bottom:12px;color:#a6a6ff}
.chart-card{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:12px;padding:16px}
.modal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.7);backdrop-filter:blur(8px);z-index:1000}
.modal-card{width:min(860px,92vw);max-height:92vh;overflow-y:auto;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.5);padding:18px}
.modal-hd{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--border-color)}
.modal-title{font-size:14px;font-weight:900;color:#66cfff}
.modal-close{border:none;background:transparent;color:var(--text-muted);font-size:24px;cursor:pointer}
.modal-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.modal-section{background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:10px;padding:10px}
.modal-section h4{font-size:10px;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px}
.recs{margin-top:8px}.recs li{margin-left:16px}
.doc-accordion{max-width:1000px;margin:0 auto;display:grid;gap:10px}
.doc-item{background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:10px;padding:12px}
.doc-q{font-size:15px;font-weight:900;letter-spacing:.3px;cursor:pointer;font-family:'Inter',sans-serif;color:#eaf1f7}
.doc-q::marker{color:#66cfff}
.doc-a{padding-top:8px;color:var(--text-secondary);font-size:13px;line-height:1.85;font-family:'Inter',sans-serif}
.doc-prose{max-width:1000px;margin:0 auto;font-size:13px;color:var(--text-secondary);line-height:1.85;font-family:'Inter',sans-serif}
.doc-prose p{margin:0 0 12px 0}
.doc-empty{opacity:.7}
.config-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
.config-input, .config-textarea{background:var(--bg-primary);border:1px solid var(--border-color);color:var(--text-primary);padding:10px 12px;border-radius:10px;font-size:12px;font-family:'JetBrains Mono',monospace}
.config-textarea{height:120px;resize:vertical}
.config-label{font-size:11px;font-weight:800;color:var(--text-secondary);margin-bottom:6px;text-transform:uppercase;letter-spacing:.6px}
@media (max-width:768px){.sidebar{width:100%;position:static;height:auto}.main-content{margin-left:0}.modal-grid{grid-template-columns:1fr}}
</style>
</head>
<body data-theme="dark">
<div class="container">
  <div class="sidebar">
    <div class="sidebar-header">
      <img src="/logo" alt="DRŚYA Logo" class="logo" onerror="this.style.display='none'">
      <div class="brand-block">
        <div class="brand-title">DRŚYA</div>
        <div class="brand-subtitle">Security Monitor</div>
      </div>
    </div>

    <div class="nav-menu">
      <div class="nav-item"><a class="nav-link active" onclick="showPage('dashboard')"><span class="nav-icon">📊</span><span>Dashboard</span></a></div>
      <div class="nav-item"><a class="nav-link" onclick="showPage('config')"><span class="nav-icon">⚙️</span><span>Configuration</span></a></div>
      <div class="nav-item strict-only"><a class="nav-link" onclick="showPage('summary')"><span class="nav-icon">📈</span><span>Summary</span></a></div>
      <div class="nav-item"><a class="nav-link" onclick="showPage('manual')"><span class="nav-icon">📘</span><span>User Manual</span></a></div>
      <div class="nav-item"><a class="nav-link" onclick="showPage('faq')"><span class="nav-icon">❓</span><span>FAQs</span></a></div>
    </div>

    <div class="mode-controls">
      <div class="section-label">Security Mode</div>
      <div class="bottom-toggle">
        <span id="mode-text" style="font-size:12px;font-weight:900">Strict</span>
        <div class="switch-rail strict" id="mode-rail"><div class="switch-knob"></div></div>
      </div>
      <div class="section-label" style="margin-top:10px">Theme</div>
      <div class="bottom-toggle">
        <span id="theme-text" style="font-size:12px;font-weight:900">Dark</span>
        <div class="switch-rail" id="theme-rail"><div class="switch-knob" id="theme-knob"></div></div>
      </div>
    </div>
  </div>

  <div class="main-content">
    <div class="header">
      <div class="header-left">
        <h1>DRŚYA Security Monitor</h1>
        <p>Real-time threat detection system</p>
      </div>
      <div class="status-badge status-inactive" id="status-badge">
        <div class="status-dot"></div><span id="status-text">Inactive</span>
      </div>
    </div>

    <!-- Dashboard -->
    <div id="dashboard" class="page active">
      <div class="dashboard-content maxw">
        <div class="control-section">
          <div class="control-header">
            <div class="control-title">System Control</div>
            <div class="control-buttons">
              <button class="btn btn-start" id="start-btn">Start</button>
              <button class="btn btn-stop" id="stop-btn" disabled>Stop</button>
            </div>
          </div>
          <div class="control-info"><span id="scan-info">Last scan: Never</span></div>
        </div>

        <div class="metrics-grid">
          <div class="metric-card"><div class="metric-number metric-total" id="total-threats">0</div><div class="metric-label">Total</div></div>
          <div class="metric-card"><div class="metric-number metric-high" id="high-threats">0</div><div class="metric-label">High</div></div>
          <div class="metric-card"><div class="metric-number metric-medium" id="medium-threats">0</div><div class="metric-label">Medium</div></div>
          <div class="metric-card"><div class="metric-number metric-low" id="low-threats">0</div><div class="metric-label">Low</div></div>
        </div>

        <div class="threats-section">
          <div class="threats-header"><div class="threats-title">Detected Threats</div></div>
          <table class="threats-table">
            <thead>
              <tr><th>PID</th><th>Name</th><th>Type</th><th>Priority</th><th>Access</th><th>Action</th></tr>
            </thead>
            <tbody id="threats-tbody"><tr><td colspan="6" class="no-threats">No threats detected. Click Start to begin monitoring.</td></tr></tbody>
          </table>
        </div>

        <div class="activity-feed">
          <div class="activity-title">Recent Activity</div>
          <div id="activity-list"></div>
        </div>
      </div>
    </div>

    <!-- Summary (strict only via JS) -->
    <div id="summary" class="page">
      <div class="dashboard-content maxw">
        <div class="control-section">
          <div class="control-title">Threat Detection Overview</div>
          <div class="metrics-grid" style="margin-top:10px">
            <div class="metric-card"><div class="metric-number" id="uptime-stat">0s</div><div class="metric-label">Uptime</div></div>
            <div class="metric-card"><div class="metric-number" id="scans-stat">0</div><div class="metric-label">Total Scanned</div></div>
            <div class="metric-card"><div class="metric-number" id="neutralized-stat">0</div><div class="metric-label">Neutralized</div></div>
            <div class="metric-card"><div class="metric-number" id="mode-stat">Strict</div><div class="metric-label">Mode</div></div>
            <div class="metric-card"><div class="metric-number" id="safe-stat">0</div><div class="metric-label">Safe Processes</div></div>
            <div class="metric-card"><div class="metric-number" id="scan-time-stat">-</div><div class="metric-label">Scan Time</div></div>
          </div>
          <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-top:12px">
            <div class="chart-card"><div class="control-title">Threat Severity Distribution</div><canvas id="sevChart" height="220"></canvas></div>
            <div class="chart-card"><div class="control-title">Resource Access Breakdown</div><canvas id="accChart" height="220"></canvas></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Manual -->
    <div id="manual" class="page">
      <div class="dashboard-content maxw">
        <div class="control-section">
          <div class="control-title">User Manual</div>
          <div id="manual-content" style="margin-top:12px"></div>
        </div>
      </div>
    </div>

    <!-- FAQ -->
    <div id="faq" class="page">
      <div class="dashboard-content maxw">
        <div class="control-section">
          <div class="control-title">Frequently Asked Questions</div>
          <div id="faq-content" style="margin-top:12px"></div>
        </div>
      </div>
    </div>

    <!-- Configuration -->
    <div id="config" class="page">
      <div class="dashboard-content maxw">
        <div class="control-section">
          <div class="control-title">Security Configuration</div>
          <div class="config-grid" style="margin-top:10px">
            <div>
              <div class="config-label">Scan Refresh Rate (seconds)</div>
              <input type="number" id="cfg-refresh" class="config-input" min="1" max="60" value="5">
            </div>
            <div>
              <div class="config-label">Auto-Kill High (Strict)</div>
              <input type="checkbox" id="cfg-autokill">
            </div>
            <div>
              <div class="config-label">Manual Path (optional)</div>
              <input type="text" id="cfg-manual" class="config-input" placeholder="/path/to/User Manual.docx">
            </div>
            <div>
              <div class="config-label">Whitelist (one per line)</div>
              <textarea id="cfg-wl" class="config-textarea" placeholder="trusted-process-1&#10;trusted-process-2"></textarea>
            </div>
            <div>
              <div class="config-label">Prevention List (Protect)</div>
              <textarea id="cfg-deny" class="config-textarea" placeholder="process-to-auto-suspend"></textarea>
            </div>
          </div>
          <div style="margin-top:12px">
            <button id="cfg-save" class="btn btn-start">Save Configuration</button>
          </div>
        </div>

        <div class="control-section">
          <div class="control-title">Power BI Streaming Integration</div>
          <div class="config-grid" style="margin-top:10px">
            <div>
              <div class="config-label">Power BI Push URL</div>
              <input type="text" id="pbi-url" class="config-input" placeholder="https://api.powerbi.com/beta/.../rows?key=...">
              <div style="margin-top:8px">
                <input type="checkbox" id="pbi-spaced"> <span style="font-size:12px;color:var(--text-secondary)">Dataset uses spaced field names (e.g., “scan time”)</span>
              </div>
            </div>
            <div>
              <div class="config-label">Actions</div>
              <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:6px">
                <button class="btn btn-start" id="pbi-save">Save URL</button>
                <button class="btn btn-export" id="pbi-test">Test Push</button>
                <button class="btn btn-stop" id="pbi-auto">Auto-stream: Off</button>
              </div>
              <div id="pbi-hint" style="margin-top:10px;color:var(--text-secondary);font-size:12px">Status: not configured</div>
            </div>
          </div>
        </div>

      </div>
    </div>

  </div>
</div>

<!-- Intel modal (Strict only) -->
<div class="modal strict-only" id="intel-modal">
  <div class="modal-card">
    <div class="modal-hd">
      <div class="modal-title" id="intel-title">Threat Intelligence</div>
      <button class="modal-close" id="intel-close">×</button>
    </div>
    <div class="modal-grid">
      <div class="modal-section">
        <h4>CVE References</h4>
        <ul id="intel-cve"></ul>
      </div>
      <div class="modal-section">
        <h4>MITRE ATT&CK</h4>
        <ul id="intel-mitre"></ul>
      </div>
      <div class="modal-section">
        <h4>Behavioral Indicators</h4>
        <ul id="intel-beh"></ul>
      </div>
      <div class="modal-section">
        <h4>Compliance Impact</h4>
        <ul id="intel-comp"></ul>
      </div>
    </div>
  </div>
</div>

<!-- Protect modal (Strict only) -->
<div class="modal strict-only" id="protect-modal">
  <div class="modal-card">
    <div class="modal-hd">
      <div class="modal-title" id="protect-title">Protect Process</div>
      <button class="modal-close" id="protect-close">×</button>
    </div>
    <div class="modal-section">
      <h4>Recommended steps</h4>
      <ul class="recs" id="protect-recs"></ul>
      <div style="display:flex;gap:10px;margin-top:10px">
        <button class="btn btn-protect" id="protect-go">Protect (Suspend & Prevent)</button>
      </div>
    </div>
  </div>
</div>

<script>
const socket = io();
let currentIntelPID = null;
let currentProtectPID = null;
let currentMode = 'strict';

function showPage(id){
  document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  const order = ['dashboard','config','summary','manual','faq'];
  const idx = order.indexOf(id); if (idx>=0) document.querySelectorAll('.nav-item .nav-link')[idx].classList.add('active');
}

function applyStrictVisibility(){
  const strictEls = document.querySelectorAll('.strict-only');
  strictEls.forEach(el=>{
    if(currentMode==='strict'){ el.style.display=''; }
    else { el.style.display='none'; }
  });
  const summaryLink = document.querySelector('.nav-item.strict-only');
  if(summaryLink){ summaryLink.style.display = (currentMode==='strict' ? '' : 'none'); }
  if(currentMode==='lenient' && document.getElementById('summary').classList.contains('active')){ showPage('dashboard'); }
}

/* NEW: lock/unlock config when switching modes */
function lockConfigForm(readOnly){
  const cfg = document.getElementById('config');
  if (!cfg) return;
  cfg.querySelectorAll('input, textarea, button').forEach(el=>{
    const isButton = (el.tagName === 'BUTTON');
    const isCheckbox = (el.type === 'checkbox');
    if (isButton || isCheckbox) {
      el.disabled = !!readOnly;
    } else {
      el.readOnly = !!readOnly;
      el.disabled = !!readOnly;
    }
  });
}

const themeRail = document.getElementById('theme-rail');
const themeText = document.getElementById('theme-text');
function applyTheme(theme){
  document.body.setAttribute('data-theme', theme === 'light' ? 'light' : 'dark');
  themeText.textContent = (theme === 'light' ? 'Light' : 'Dark');
  themeRail.classList.toggle('light', theme === 'light');
}
themeRail.addEventListener('click', function(){
  const newTheme = (document.body.getAttribute('data-theme') === 'light') ? 'dark' : 'light';
  applyTheme(newTheme);
  fetch('/update_config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({theme:newTheme})});
});

const modeRail = document.getElementById('mode-rail');
const modeText = document.getElementById('mode-text');
function setMode(mode){
  currentMode = mode;
  modeRail.classList.toggle('strict', mode==='strict');
  modeText.textContent = mode.charAt(0).toUpperCase()+mode.slice(1);
  applyStrictVisibility();
  lockConfigForm(mode === 'lenient'); // <-- make config read-only in lenient
}
modeRail.addEventListener('click', function(){
  const next = modeRail.classList.contains('strict') ? 'lenient' : 'strict';
  fetch('/switch_mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:next})})
    .then(function(){ setMode(next); });
});

document.getElementById('start-btn').addEventListener('click',function(){
  fetch('/start_monitoring',{method:'POST'}).then(function(){setActive(true);});
});
document.getElementById('stop-btn').addEventListener('click',function(){
  fetch('/stop_monitoring',{method:'POST'}).then(function(){setActive(false);clearThreats();});
});

function setActive(on){
  const badge=document.getElementById('status-badge'), text=document.getElementById('status-text'),
        startBtn=document.getElementById('start-btn'), stopBtn=document.getElementById('stop-btn');
  if(on){badge.classList.remove('status-inactive'); badge.classList.add('status-active'); text.textContent='Active'; startBtn.disabled=true; stopBtn.disabled=false;}
  else {badge.classList.add('status-inactive'); badge.classList.remove('status-active'); text.textContent='Inactive'; startBtn.disabled=false; stopBtn.disabled=true;}
}

function clearThreats(){
  const tbody=document.getElementById('threats-tbody');
  tbody.innerHTML='<tr><td colspan="6" class="no-threats">No threats detected. Click Start to begin monitoring.</td></tr>';
  ['total-threats','high-threats','medium-threats','low-threats'].forEach(function(id){document.getElementById(id).textContent='0';});
}

function openIntelModal(row){
  if(currentMode!=='strict'){ return; }
  currentIntelPID = row.PID;
  document.getElementById('intel-title').textContent = row.Name + ' — ' + row.Type;
  const cv = document.getElementById('intel-cve'); cv.innerHTML='';
  const mi = document.getElementById('intel-mitre'); mi.innerHTML='';
  const be = document.getElementById('intel-beh'); be.innerHTML='';
  const co = document.getElementById('intel-comp'); co.innerHTML='';
  const intel = row.Intel || {cve:[],mitre:[],behavior:[],compliance:[]};
  (intel.cve||[]).forEach(c=>{ const li=document.createElement('li'); li.textContent = c.id + ' (CVSS ' + c.cvss + ') — ' + c.hint; cv.appendChild(li); });
  (intel.mitre||[]).forEach(m=>{ const li=document.createElement('li'); li.textContent = m.id + ': ' + m.name; mi.appendChild(li); });
  (intel.behavior||[]).forEach(b=>{ const li=document.createElement('li'); li.textContent = b; be.appendChild(li); });
  (intel.compliance||[]).forEach(c=>{ const li=document.createElement('li'); li.textContent = c; co.appendChild(li); });
  document.getElementById('intel-modal').style.display='flex';
}
document.getElementById('intel-close').addEventListener('click', ()=>{document.getElementById('intel-modal').style.display='none'; currentIntelPID=null;});

function openProtectModal(row){
  if(currentMode!=='strict'){ return; }
  currentProtectPID = row.PID;
  document.getElementById('protect-title').textContent = 'Protect: ' + row.Name + ' — ' + row.Type;
  const rc = document.getElementById('protect-recs'); rc.innerHTML='';
  (row.Recs||[]).forEach(r=>{ const li=document.createElement('li'); li.textContent = r; rc.appendChild(li); });
  document.getElementById('protect-modal').style.display='flex';
}
document.getElementById('protect-close').addEventListener('click', ()=>{document.getElementById('protect-modal').style.display='none'; currentProtectPID=null;});
document.getElementById('protect-go').addEventListener('click', function(){
  if(currentProtectPID==null) return;
  fetch('/restore_process',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:currentProtectPID})})
  .then(r=>r.json()).then(res=>{
    alert((res.status==='restored'?'Success: ':'Failed: ') + (res.message||'')); 
    document.getElementById('protect-modal').style.display='none';
  }).catch(err=>alert('Network error: ' + err.message));
});

function killPID(pid){
  if(!confirm('Kill process with PID ' + pid + '?')) return;
  fetch('/kill_process',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:pid})})
  .then(r=>r.json()).then(res=>{
    alert((res.status==='killed'?'Success: ':'Failed: ') + (res.message||'')); 
  }).catch(err=>alert('Network error: ' + err.message));
}

function rowActionsHTML(r){
  const nvdq = encodeURIComponent(r.Name || '');
  const intelUrl='https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=' + nvdq + '&isCpeNameSearch=false';
  let html = '';
  html += '<button class="action-btn btn-intel" onclick="window.open(\''+intelUrl+'\',\'_blank\')">NVD</button>';
  if(currentMode==='strict'){
    html += '<button class="action-btn btn-intel strict-only" onclick="openIntelModal('+JSON.stringify(r).replace(/"/g,'&quot;')+')">Intel</button>';
    html += '<button class="action-btn btn-protect strict-only" onclick="openProtectModal('+JSON.stringify(r).replace(/"/g,'&quot;')+')">Protect</button>';
  }
  html += '<button class="action-btn btn-stop" onclick="killPID('+r.PID+')">Kill</button>';
  return html;
}

socket.on('threat_update', function(payload){
  const s=payload.summary, st=payload.status;
  setMode(st.mode);

  document.getElementById('total-threats').textContent=s.total;
  document.getElementById('high-threats').textContent=s.high;
  document.getElementById('medium-threats').textContent=s.medium;
  document.getElementById('low-threats').textContent=s.low;
  document.getElementById('scan-info').textContent='Last scan: ' + (st.last_scan||'-');

  document.getElementById('uptime-stat').textContent = st.uptime + 's';
  document.getElementById('scans-stat').textContent = s.total_scanned || 0;
  document.getElementById('neutralized-stat').textContent = s.neutralized || 0;
  document.getElementById('mode-stat').textContent = st.mode || 'Strict';
  document.getElementById('safe-stat').textContent = s.safe_processes || 0;
  document.getElementById('scan-time-stat').textContent = (st.scan_time||'-') + 's';

  const list=document.getElementById('activity-list'); list.innerHTML='';
  (payload.activity||[]).forEach(function(a){
    const div = document.createElement('div');
    div.innerHTML = '<div style="font-size:12px;color:#eaf1f7">'+a.message+'</div><div style="font-size:10px;color:#a7b4c6;margin-top:3px">'+a.time_display+'</div>';
    list.appendChild(div);
  });

  const tbody=document.getElementById('threats-tbody'); tbody.innerHTML='';
  const rows = payload.threats || [];
  if(rows.length===0){
    tbody.innerHTML='<tr><td colspan="6" class="no-threats">No threats detected.</td></tr>';
  } else {
    rows.forEach(function(r){
      const cls = r.Priority==='High'?'priority-high':(r.Priority==='Medium'?'priority-medium':'priority-low');
      const actions = rowActionsHTML(r);
      tbody.insertAdjacentHTML('beforeend',
        '<tr>' +
          '<td>'+r.PID+'</td>' +
          '<td>'+r.Name+'</td>' +
          '<td>'+r.Type+'</td>' +
          '<td><span class="priority-badge '+cls+'">'+r.Priority+'</span></td>' +
          '<td>'+r.Access+'</td>' +
          '<td>'+actions+'</td>' +
        '</tr>'
      );
    });
  }

  updateCharts({
    high:s.high, medium:s.medium, low:s.low,
    access: payload.access_counts || {}
  });
});

// charts
let sevChart=null, accChart=null;
function updateCharts(data){
  if(currentMode!=='strict') return;
  const sevCtx=document.getElementById('sevChart').getContext('2d');
  const accCtx=document.getElementById('accChart').getContext('2d');
  const sevData = [data.high||0, data.medium||0, data.low||0];
  const accLabels = Object.keys(data.access||{});
  const accData = accLabels.map(k=>data.access[k]);
  if(sevChart){sevChart.destroy()}
  sevChart = new Chart(sevCtx,{type:'doughnut',data:{labels:['High','Medium','Low'],datasets:[{data:sevData}]}});
  if(accChart){accChart.destroy()}
  accChart = new Chart(accCtx,{type:'bar',data:{labels:accLabels,datasets:[{data:accData}]},options:{scales:{y:{beginAtZero:true}}}});
}

// -------- Config load/save --------
function loadConfigToForm(){
  fetch('/api/status').then(r=>r.json()).then(j=>{
    const cfg = (j.data && j.data.config) || {};
    document.getElementById('cfg-refresh').value = cfg.refresh_rate || 5;
    document.getElementById('cfg-autokill').checked = !!cfg.auto_kill_high;
    document.getElementById('cfg-manual').value = cfg.manual_path || '';
    document.getElementById('cfg-wl').value = (cfg.whitelist||[]).join('\n');
    document.getElementById('cfg-deny').value = (cfg.denylist||[]).join('\n');

    document.getElementById('pbi-url').value = cfg.powerbi_url || '';
    document.getElementById('pbi-spaced').checked = !!cfg.powerbi_spaced_fields;
    const autoBtn = document.getElementById('pbi-auto');
    autoBtn.textContent = 'Auto-stream: ' + (cfg.powerbi_auto ? 'On' : 'Off');
    const hint = document.getElementById('pbi-hint');
    hint.textContent = (cfg.powerbi_url ? 'Status: URL configured' : 'Status: not configured');

    // enforce readonly if mode is lenient at load time
    lockConfigForm((j.data && j.data.mode) === 'lenient');
  }).catch(()=>{});
}
document.getElementById('cfg-save').addEventListener('click', function(){
  const payload = {
    refresh_rate: parseInt(document.getElementById('cfg-refresh').value||'5'),
    auto_kill_high: document.getElementById('cfg-autokill').checked,
    manual_path: document.getElementById('cfg-manual').value || '',
    whitelist: document.getElementById('cfg-wl').value,
    denylist: document.getElementById('cfg-deny').value
  };
  fetch('/update_config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
  .then(r=>r.json()).then(res=>{
    if(res.status==='success'){ alert('Configuration saved'); loadConfigToForm(); }
    else { alert('Save failed: ' + (res.message||'Unknown error')); }
  }).catch(err=>alert('Network error: ' + err.message));
});

// Power BI controls
document.getElementById('pbi-save').addEventListener('click', function(){
  const payload = {
    powerbi_url: document.getElementById('pbi-url').value || '',
    powerbi_spaced_fields: document.getElementById('pbi-spaced').checked
  };
  fetch('/update_config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
  .then(r=>r.json()).then(res=>{
    if(res.status==='success'){ alert('Power BI settings saved'); loadConfigToForm(); }
    else { alert('Save failed: ' + (res.message||'Unknown error')); }
  }).catch(err=>alert('Network error: ' + err.message));
});

document.getElementById('pbi-test').addEventListener('click', function(){
  fetch('/push_powerbi',{method:'POST'}).then(r=>r.json()).then(res=>{
    alert((res.success?'Success: ':'Failed: ') + (res.message||''));
  }).catch(err=>alert('Network error: ' + err.message));
});

document.getElementById('pbi-auto').addEventListener('click', function(){
  const btn = this;
  const nowOn = (btn.textContent.indexOf('On')>=0);
  const enable = !nowOn;
  const payload = {
    enable: enable,
    url: document.getElementById('pbi-url').value || '',
    spaced_fields: document.getElementById('pbi-spaced').checked
  };
  fetch('/powerbi_auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
  .then(r=>r.json()).then(res=>{
    if(res.success){
      btn.textContent = 'Auto-stream: ' + (res.status==='on'?'On':'Off');
    } else {
      alert('Failed toggling auto-stream');
    }
  }).catch(err=>alert('Network error: ' + err.message));
});

document.addEventListener('DOMContentLoaded', function(){
  applyStrictVisibility();
  loadConfigToForm();
  const manualHTML = document.getElementById('manual-html').textContent || '';
  const faqHTML = document.getElementById('faq-html').textContent || '';
  document.getElementById('manual-content').innerHTML = manualHTML;
  document.getElementById('faq-content').innerHTML = faqHTML;

  // initial lock based on default currentMode
  lockConfigForm(currentMode === 'lenient');
});
</script>

<script id="manual-html" type="text/plain">''' + manual_html + '''</script>
<script id="faq-html" type="text/plain">''' + faq_html + '''</script>
</body>
</html>'''

@app.route('/')
def dashboard():
    manual_txt = ""
    mp = (config.get('manual_path') or "").strip()
    if mp and os.path.exists(mp):
        if mp.lower().endswith('.docx'):
            manual_txt = load_docx_text(mp)
        else:
            manual_txt = load_textfile_safe(mp)
    if not manual_txt:
        manual_txt = EMBEDDED_MANUAL
    faq_txt = EMBEDDED_FAQ
    manual_html = render_manual_html(manual_txt)
    faq_html = render_faq_html(faq_txt)
    return render_template_string(html_page(manual_html, faq_html))

@socketio.on('connect')
def on_connect():
    emit('connected', {'config': config, 'mode': current_mode})

def main():
    global current_mode, safe_text_entered
    parser = argparse.ArgumentParser(description="DRŚYA Security Monitor")
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--mode', choices=['strict','lenient'], default='strict', help='Security mode')
    args = parser.parse_args()

    current_mode = args.mode

    try:
        st = os.environ.get('DRSYA_SAFE_TEXT_PROMPT','0')
        if st == '1':
            txt = getpass.getpass("Enter safe text (hidden): ").strip()
            safe_text_entered = bool(txt)
    except Exception:
        pass

    print(f"[*] DRŚYA Security Monitor starting...")
    print(f"[*] Host: {args.host}")
    print(f"[*] Port: {args.port}")
    print(f"[*] Mode: {current_mode.upper()}")
    print(f"[*] Dashboard: http://{args.host}:{args.port}")
    print(f"[*] Logo path: {config.get('logo_path', 'Not configured')}")
    print(f"[*] Manual path: {config.get('manual_path', 'Embedded')}")
    print(f"[*] Background: {config.get('background_path', 'Embedded')}")

    socketio.run(app, host=args.host, port=args.port, debug=True, allow_unsafe_werkzeug=True)

if __name__ == "__main__":
    main()


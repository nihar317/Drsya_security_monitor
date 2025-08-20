#!/usr/bin/env python3
"""
Simple working version of Dṛśya Monitor
This will definitely work and show output
"""

print("Starting Dṛśya Monitor...")

import sys
import os

# Check Python version
print(f"Python version: {sys.version}")

# Try imports with error handling
try:
    from flask import Flask, render_template_string, request, jsonify
    print("✅ Flask imported successfully")
except ImportError as e:
    print(f"❌ Flask import failed: {e}")
    print("Installing Flask...")
    os.system("pip3 install flask")
    sys.exit(1)

try:
    from flask_socketio import SocketIO, emit
    print("✅ Flask-SocketIO imported successfully")
except ImportError as e:
    print(f"❌ Flask-SocketIO import failed: {e}")
    print("Installing Flask-SocketIO...")
    os.system("pip3 install flask-socketio")
    sys.exit(1)

try:
    import psutil
    print("✅ psutil imported successfully")
except ImportError as e:
    print(f"❌ psutil import failed: {e}")
    print("Installing psutil...")
    os.system("pip3 install psutil")
    sys.exit(1)

import time
import threading
import webbrowser
import argparse
from datetime import datetime

print("All imports successful!")

# Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'drsya-2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
is_monitoring = False
threats_detected = []
scan_count = 0

# HTML Dashboard
HTML_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <title>Dṛśya Security Monitor</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1b3a 100%);
            color: #e0e6ed;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(22, 33, 62, 0.9);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid #2a3f5f;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 1.5rem;
            font-weight: bold;
            color: #00d9ff;
        }
        
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: rgba(22, 33, 62, 0.8);
            border: 1px solid #2a3f5f;
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
        }
        
        .stat-label {
            font-size: 0.875rem;
            color: #a8b2d1;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.5rem;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: #00d9ff;
        }
        
        .control-panel {
            background: rgba(22, 33, 62, 0.8);
            border: 1px solid #2a3f5f;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            backdrop-filter: blur(10px);
        }
        
        .btn {
            padding: 0.75rem 2rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-right: 1rem;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #00d9ff, #00ff88);
            color: #0f0f23;
        }
        
        .btn-danger {
            background: #ff4757;
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 217, 255, 0.3);
        }
        
        .threat-table {
            background: rgba(22, 33, 62, 0.8);
            border: 1px solid #2a3f5f;
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            text-align: left;
            padding: 1rem;
            font-size: 0.875rem;
            color: #a8b2d1;
            border-bottom: 2px solid #2a3f5f;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        td {
            padding: 1rem;
            border-bottom: 1px solid #2a3f5f;
        }
        
        .status-active {
            color: #00ff88;
        }
        
        .status-inactive {
            color: #ff4757;
        }
        
        .priority-high { color: #ff4757; }
        .priority-medium { color: #ffa502; }
        .priority-low { color: #00ff88; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">
            <i class="fas fa-eye"></i>
            <span>DṚŚYA SECURITY MONITOR</span>
        </div>
        <div>
            <span id="status" class="status-inactive">● Inactive</span>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Threats</div>
                <div class="stat-value" id="totalThreats">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High Priority</div>
                <div class="stat-value" style="color: #ff4757;" id="highPriority">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Scans</div>
                <div class="stat-value" style="color: #00ff88;" id="scanCount">0</div>
            </div>
        </div>
        
        <div class="control-panel">
            <h3 style="margin-bottom: 1rem;">Monitoring Controls</h3>
            <button class="btn btn-primary" onclick="startMonitoring()">
                <i class="fas fa-play"></i> Start Monitoring
            </button>
            <button class="btn btn-danger" onclick="stopMonitoring()">
                <i class="fas fa-stop"></i> Stop
            </button>
        </div>
        
        <div class="threat-table">
            <h3 style="margin-bottom: 1rem;">Detected Threats</h3>
            <table>
                <thead>
                    <tr>
                        <th>PID</th>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Priority</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="threatTable">
                    <tr>
                        <td colspan="5" style="text-align: center; color: #a8b2d1;">
                            No threats detected. Start monitoring to begin.
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        const socket = io();
        
        socket.on('connect', () => {
            console.log('Connected to server');
        });
        
        socket.on('update', (data) => {
            document.getElementById('totalThreats').textContent = data.total || 0;
            document.getElementById('highPriority').textContent = data.high || 0;
            document.getElementById('scanCount').textContent = data.scans || 0;
            
            const tbody = document.getElementById('threatTable');
            if (data.threats && data.threats.length > 0) {
                tbody.innerHTML = data.threats.map(t => `
                    <tr>
                        <td>${t.pid}</td>
                        <td>${t.name}</td>
                        <td>${t.type}</td>
                        <td class="priority-${t.priority.toLowerCase()}">${t.priority}</td>
                        <td><button onclick="killProcess(${t.pid})">Kill</button></td>
                    </tr>
                `).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #a8b2d1;">No threats detected</td></tr>';
            }
        });
        
        function startMonitoring() {
            fetch('/api/start', {method: 'POST'})
                .then(() => {
                    document.getElementById('status').className = 'status-active';
                    document.getElementById('status').textContent = '● Active';
                });
        }
        
        function stopMonitoring() {
            fetch('/api/stop', {method: 'POST'})
                .then(() => {
                    document.getElementById('status').className = 'status-inactive';
                    document.getElementById('status').textContent = '● Inactive';
                });
        }
        
        function killProcess(pid) {
            if (confirm('Kill process ' + pid + '?')) {
                fetch('/api/kill', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({pid: pid})
                });
            }
        }
    </script>
</body>
</html>'''

# Monitoring function
def scan_for_threats():
    """Scan for suspicious processes"""
    threats = []
    suspicious_keywords = {
        "keylog": ("Keylogger", "High"),
        "wireshark": ("Network Spy", "Medium"),
        "tcpdump": ("Network Spy", "Medium"),
        "mic": ("Mic Access", "Medium"),
        "camera": ("Camera Access", "High"),
    }
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            for keyword, (threat_type, priority) in suspicious_keywords.items():
                if keyword in name:
                    threats.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'type': threat_type,
                        'priority': priority
                    })
                    break
        except:
            pass
    
    return threats

def monitoring_loop():
    """Main monitoring loop"""
    global is_monitoring, threats_detected, scan_count
    
    while is_monitoring:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning...")
        threats = scan_for_threats()
        threats_detected = threats
        scan_count += 1
        
        high_count = len([t for t in threats if t['priority'] == 'High'])
        
        # Emit update
        socketio.emit('update', {
            'threats': threats,
            'total': len(threats),
            'high': high_count,
            'scans': scan_count
        })
        
        print(f"  Found {len(threats)} threats")
        time.sleep(10)

# Flask routes
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    global is_monitoring
    if not is_monitoring:
        is_monitoring = True
        thread = threading.Thread(target=monitoring_loop)
        thread.daemon = True
        thread.start()
        print("✅ Monitoring started")
    return jsonify({'status': 'started'})

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    global is_monitoring
    is_monitoring = False
    print("⏹️ Monitoring stopped")
    return jsonify({'status': 'stopped'})

@app.route('/api/kill', methods=['POST'])
def kill_process():
    data = request.get_json()
    pid = data.get('pid')
    try:
        psutil.Process(pid).kill()
        print(f"💀 Killed process {pid}")
        return jsonify({'status': 'killed'})
    except:
        return jsonify({'status': 'error'})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--strict', action='store_true')
    parser.add_argument('--lenient', action='store_true')
    args = parser.parse_args()
    
    print("=" * 60)
    print("🛡️  DṚŚYA SECURITY MONITOR")
    print("=" * 60)
    print(f"Port: {args.port}")
    print(f"Mode: {'Strict' if args.strict else 'Lenient'}")
    print(f"Dashboard: http://localhost:{args.port}")
    print("=" * 60)
    
    # Open browser after 3 seconds
    def open_browser():
        time.sleep(3)
        webbrowser.open(f'http://localhost:{args.port}')
        print("🌐 Browser opened")
    
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run Flask
    print("🚀 Starting Flask server...")
    try:
        socketio.run(app, host='0.0.0.0', port=args.port, debug=False)
    except Exception as e:
        print(f"❌ Error starting server: {e}")

if __name__ == "__main__":
    main()

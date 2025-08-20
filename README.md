# Security Monitor Dashboard

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-green.svg)
![Flask](https://img.shields.io/badge/flask-2.3+-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

**Real-time Process Monitoring & Threat Detection System**

A sophisticated security monitoring dashboard built with Flask that provides real-time detection of suspicious processes, keyloggers, and potential security threats. Features **Strict** and **Lenient** modes, modern UI, Intel & Protect workflows, and optional Power BI streaming.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Data Layer      │────│ Analysis Layer   │────│ Interface Layer │
│                 │    │                  │    │                 │
│ • Process Data  │    │ • Real-time Scan │    │ • Web Dashboard │
│ • Safe Registry │    │ • Classification │    │ • Launcher UI   │
│ • Threat Sigs   │    │ • Intel/Protect  │    │ • Real-time WS  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites
- Python **3.11+**
- Web Browser
- Git
- Administrative privileges (recommended for Kill/Protect features)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/Drsya_security_monitor.git
cd Drsya_security_monitor

# 2. Create virtual environment
python -m venv venv

# 3. Activate environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux/Mac:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the application
# Strict mode (Intel + Protect + NVD + Kill, editable config)
python drsya_app.py --mode strict

# OR Lenient mode (NVD + Kill, read-only config)
python drsya_app.py --mode lenient
```

### Access Dashboard
Open your browser to: **http://localhost:5000**

## Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Backend | Python 3.11 | Core application logic |
| Web Framework | Flask | HTTP server & routing |
| Real-time | Flask-SocketIO | WebSocket communication |
| System Monitoring | psutil | Process & system data |
| Frontend | HTML5/CSS3/JS | User interface |
| Data Format | JSON | API communication |
| Visualization (opt.) | Power BI Streaming | External dashboards |

## Project Structure

```
Drsya_security_monitor/
├── drsya_app.py                # Main Flask application (dashboard/API)
├── drsya_launcher.py           # Launcher (optional)
├── extensions/                 # Web extension (optional)
├── assets/
│   ├── logo/final_icon.jpg     # App logo image
│   └── backgrounds/circuit_bg.jpg
├── docs/
│   ├── user_manual.md
│   └── faq.md
├── scripts/
│   ├── run.sh
│   └── run_lenient.sh
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git exclusions
└── README.md                   # Project documentation
```

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| Real-time Monitoring | ✅ Active | Live scans with WebSocket updates |
| Threat Classification | ✅ Active | High / Medium / Low priorities |
| Web Dashboard | ✅ Active | Modern responsive interface |
| Theme Support | ✅ Active | Dark theme with subtle background |
| Process Termination | ✅ Active | Kill action (both modes) |
| Intel (Strict) | ✅ Active | MITRE, CVE hints, behavior & compliance |
| Protect (Strict) | ✅ Active | Preventive recommendations & auto-suspend |
| Summary (Strict) | ✅ Active | Charts, uptime, distribution |
| Configuration UI | ✅ Active | Editable in Strict, read-only in Lenient |
| Power BI (opt.) | ✅ Active | Test push & auto-stream |

## Threat Detection Logic

### Classification System

```python
THREAT_PRIORITIES = {
    "HIGH": {
        "triggers": ["keylog", "keylogger", "intercept", "keystroke", "rat", "reverse"],
        "risk": "Direct credential/data capture or remote control",
        "action": "Immediate termination or Protect"
    },
    "MEDIUM": {
        "triggers": ["mic", "arecord", "alsa", "v4l", "camera", "bluetoothd", "bluez"],
        "risk": "Hardware surveillance (audio/video/proximity)",
        "action": "Investigate, optionally Protect"
    },
    "LOW": {
        "triggers": ["network activity", "service"],
        "risk": "Benign or uncertain behavior",
        "action": "Monitor and whitelist if trusted"
    }
}
```

### Detection Workflow

1. **Process Enumeration** → List active processes
2. **Whitelist Filter** → Exclude trusted apps
3. **Sensor/Keyword Heuristics** → Device access + pattern match
4. **Priority Assignment** → High / Medium / Low
5. **Intel/Protect (Strict)** → Guidance & preventive actions
6. **User Action** → Kill or Protect (Strict), Kill (Lenient)

## Interface Components

### Navigation Structure
- **Dashboard** - Main monitoring interface
- **Configuration** - Power BI, refresh rate, whitelist
- **Summary** - Strict-only charts & intel rollup
- **User Manual** - Guided help
- **FAQs** - Troubleshooting

### Dashboard Elements
- **Statistics Cards**: Total/High/Medium/Low counters
- **Process Table**: PID, Name, Type, Priority, Access, Actions
- **Actions**:
  - **Strict**: Intel • Protect • NVD • Kill
  - **Lenient**: NVD • Kill
- **Control Panel**: Start/Stop monitoring
- **Theme Toggle**: Dark (default)

## Configuration

### Command Line Arguments

```bash
python drsya_app.py --mode strict        # or --mode lenient
python drsya_app.py --host 127.0.0.1 --port 5000
```

### Configuration File (Optional)

Create `config.json`:

```json
{
  "refresh_rate": 5,
  "auto_kill_high": false,
  "theme": "dark",
  "notifications": true,
  "whitelist": ["systemd","pipewire","chrome","firefox"],
  "denylist": [],
  "logo_path": "assets/logo/final_icon.jpg",
  "background_path": "assets/backgrounds/circuit_bg.jpg",
  "powerbi_url": "",
  "powerbi_auto": false,
  "powerbi_spaced_fields": false
}
```

## Testing & Development

### Development Mode

```bash
# Windows PowerShell
$env:FLASK_DEBUG=1
python drsya_app.py --mode strict
```

### Generate Dependencies

```bash
pip freeze > requirements.txt
```

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Serve dashboard |
| `/start_monitoring` | POST | Begin scanning |
| `/stop_monitoring` | POST | Stop scanning |
| `/api/scan` | POST | One-shot scan |
| `/kill_process` | POST | Terminate specific PID |
| `/protect_process` | POST | Protect/suspend PID (Strict) |

## Performance Metrics

### System Requirements
- **Memory**: ~50MB base + process list
- **CPU**: typically <5% during scans
- **Disk**: ~10MB install footprint
- **Network**: Local WebSocket only (Power BI is outbound if enabled)

### Scan Performance (typical)
- **Process enumeration**: ~100ms
- **Heuristics & classify**: ~50ms per process
- **UI update**: ~10ms
- **Cycle**: ~1–2 seconds

## Troubleshooting

### Common Issues

**"No module named 'psutil'"**
```bash
pip install -r requirements.txt
```

**"Port 5000 already in use"**
```bash
python drsya_app.py --port 8080
```

**"Kill/Protect failed: Access denied"**
Run terminal as Administrator (Windows) or use sudo (Linux).

**"Dashboard won't load"**
```bash
# Check if server is running
netstat -an | findstr :5000
```

## Security Considerations

### Permissions
- Process termination/suspension may require elevated privileges
- Lenient mode can be used for safe read-only monitoring

### Data Privacy
- Local operation by default
- No data storage unless Power BI streaming is enabled

## Contributing

### Development Workflow
1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Implement and test
4. Commit with clear messages
5. Submit a pull request

### Code Style
- **Python**: PEP 8
- **JavaScript**: ES6+
- **CSS**: Utility-first & variables
- **Docs**: Markdown

## Future Enhancements

### Planned Features
- [ ] Historical logging & timeline view
- [ ] Alerting (email/Slack) for High threats
- [ ] Network connection insights
- [ ] ML-based anomaly detection
- [ ] Role-based access / multi-user

## Acknowledgments

### Technologies Used
- **Flask** – Python web framework
- **Flask-SocketIO** – Real-time communication
- **psutil** – System monitoring
- **CSS Grid/Flexbox** – Responsive layouts

### Inspiration
- NIST guidance on secure monitoring
- Modern realtime dashboards UX patterns

## Getting Help

- **FAQs** – Built into the dashboard
- **User Manual** – In the UI under User Manual
- **Issue Tracking** – Use GitHub Issues for bugs/features

## Version Information

- **Current Version**: 1.0.0
- **Python Support**: 3.11+
- **Compatibility**: Windows, Linux, macOS

---

<div align="center">
 
</div>

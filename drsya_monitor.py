#!/usr/bin/env python3
"""
Dṛśya Security Monitor - Professional Edition
Complete monitor with enterprise-grade UI
"""

import psutil
import time
import argparse
import os
import threading
import json
import webbrowser
import base64
from pathlib import Path
from flask import Flask, render_template_string, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from datetime import datetime
import tempfile

# Enhanced suspicious keywords
SUSPICIOUS_KEYWORDS = {
    "Keylogger": {"keywords": ["keylog", "logger", "intercept", "keystroke", "keyspy", "keymon", "keyrecord"], "priority": "High"},
    "Mic Access": {"keywords": ["mic", "audio", "pulse", "alsa", "microphone", "record", "capture"], "priority": "Medium"},
    "Bluetooth Access": {"keywords": ["bluetoothd", "btmon", "bluetooth", "btsniff", "btscanner"], "priority": "Medium"},
    "Camera Access": {"keywords": ["v4l", "webcam", "camera", "cheese", "video", "capture", "cam"], "priority": "High"},
    "Screen Capture": {"keywords": ["screenshot", "screen", "capture", "recorder", "scrot", "spectacle"], "priority": "High"},
    "Clipboard Access": {"keywords": ["clipboard", "clip", "copy", "paste", "xclip", "xsel"], "priority": "Medium"},
    "Network Spy": {"keywords": ["wireshark", "tcpdump", "netstat", "nmap", "sniff", "packet"], "priority": "Medium"},
    "System Spy": {"keywords": ["spy", "monitor", "watch", "track", "surveillance", "stealth"], "priority": "High"},
}

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'drsya-security-monitor-2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
safe_list = set()
is_monitoring = False
monitoring_thread = None
strict_mode = False
auto_kill_enabled = False
refresh_interval = 10
current_mode = "lenient"
threats_detected = []
scan_count = 0
start_time = None
killed_processes = 0
total_processes_scanned = 0

# Professional Dashboard HTML
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dṛśya Security Monitor</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-primary: #0f0f23;
            --bg-secondary: #1a1b3a;
            --bg-card: #16213e;
            --bg-hover: #1e2f4f;
            --border-color: #2a3f5f;
            --text-primary: #e0e6ed;
            --text-secondary: #a8b2d1;
            --text-muted: #64748b;
            --accent-cyan: #00d9ff;
            --accent-green: #00ff88;
            --accent-yellow: #ffd700;
            --accent-red: #ff4757;
            --accent-orange: #ff9f43;
            --sidebar-width: 240px;
            --header-height: 60px;
        }

        [data-theme="light"] {
            --bg-primary: #f7f9fc;
            --bg-secondary: #ffffff;
            --bg-card: #ffffff;
            --bg-hover: #f1f5f9;
            --border-color: #e2e8f0;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            overflow-x: hidden;
            transition: all 0.3s ease;
        }

        /* Mode Selection Screen */
        .mode-selection {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--bg-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
        }

        .mode-selection.hidden {
            display: none;
        }

        .mode-container {
            text-align: center;
            max-width: 600px;
            padding: 2rem;
        }

        .logo-container {
            margin-bottom: 3rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1rem;
        }

        .logo-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-green));
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            color: white;
            box-shadow: 0 10px 30px rgba(0, 217, 255, 0.3);
        }

        .logo-text {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-green));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -1px;
        }

        .mode-title {
            font-size: 1.5rem;
            color: var(--text-secondary);
            margin-bottom: 2rem;
        }

        .mode-cards {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .mode-card {
            background: var(--bg-card);
            border: 2px solid var(--border-color);
            border-radius: 16px;
            padding: 2rem;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .mode-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--accent-cyan), var(--accent-green));
            transform: translateX(-100%);
            transition: transform 0.3s ease;
        }

        .mode-card:hover::before {
            transform: translateX(0);
        }

        .mode-card:hover {
            border-color: var(--accent-cyan);
            transform: translateY(-4px);
            box-shadow: 0 10px 30px rgba(0, 217, 255, 0.2);
        }

        .mode-card.selected {
            border-color: var(--accent-cyan);
            background: linear-gradient(135deg, rgba(0, 217, 255, 0.1), rgba(0, 255, 136, 0.1));
        }

        .mode-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
        }

        .mode-name {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .mode-description {
            font-size: 0.875rem;
            color: var(--text-muted);
        }

        .continue-btn {
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-green));
            color: white;
            border: none;
            padding: 1rem 3rem;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 217, 255, 0.3);
        }

        .continue-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 217, 255, 0.4);
        }

        .continue-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        /* Sidebar */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: var(--sidebar-width);
            height: 100vh;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            z-index: 100;
        }

        .sidebar-header {
            padding: 1.25rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .sidebar-logo {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-green));
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }

        .sidebar-title {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-green));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .nav-section {
            padding: 0.5rem 0;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.875rem 1.25rem;
            color: var(--text-secondary);
            text-decoration: none;
            transition: all 0.2s ease;
            cursor: pointer;
            position: relative;
            font-size: 0.9rem;
        }

        .nav-item:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
        }

        .nav-item.active {
            background: linear-gradient(90deg, rgba(0, 217, 255, 0.1), transparent);
            color: var(--accent-cyan);
        }

        .nav-item.active::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 3px;
            background: var(--accent-cyan);
        }

        /* Main Content */
        .main-container {
            margin-left: var(--sidebar-width);
            min-height: 100vh;
            background: var(--bg-primary);
        }

        .header {
            height: var(--header-height);
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 2rem;
        }

        .header-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .header-controls {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .theme-toggle {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s ease;
            color: var(--text-secondary);
        }

        .theme-toggle:hover {
            background: var(--bg-hover);
            color: var(--accent-cyan);
        }

        .mode-badge {
            padding: 0.5rem 1rem;
            background: linear-gradient(135deg, rgba(0, 217, 255, 0.1), rgba(0, 255, 136, 0.1));
            border: 1px solid var(--accent-cyan);
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--accent-cyan);
        }

        .content {
            padding: 2rem;
        }

        .content-section {
            display: none;
        }

        .content-section.active {
            display: block;
        }

        /* Dashboard Stats */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-cyan), var(--accent-green));
        }

        .stat-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            font-family: 'Space Grotesk', monospace;
            line-height: 1;
            margin-bottom: 0.5rem;
        }

        .stat-change {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        /* Control Panel */
        .control-panel {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .control-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .control-title {
            font-size: 1.125rem;
            font-weight: 600;
        }

        .status-badge {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 500;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .status-active {
            background: rgba(0, 255, 136, 0.1);
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
        }

        .status-inactive {
            background: rgba(255, 71, 87, 0.1);
            color: var(--accent-red);
            border: 1px solid var(--accent-red);
        }

        .control-buttons {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-green));
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0, 217, 255, 0.3);
        }

        .btn-danger {
            background: var(--accent-red);
            color: white;
        }

        .btn-secondary {
            background: var(--bg-hover);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }

        /* Threat Table */
        .threat-section {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .threat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .threat-table {
            width: 100%;
            border-collapse: collapse;
        }

        .threat-table th {
            text-align: left;
            padding: 0.75rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            border-bottom: 2px solid var(--border-color);
        }

        .threat-table td {
            padding: 1rem 0.75rem;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
        }

        .threat-table tbody tr:hover {
            background: var(--bg-hover);
        }

        .priority-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .priority-high {
            background: rgba(255, 71, 87, 0.1);
            color: var(--accent-red);
        }

        .priority-medium {
            background: rgba(255, 159, 67, 0.1);
            color: var(--accent-orange);
        }

        .priority-low {
            background: rgba(0, 255, 136, 0.1);
            color: var(--accent-green);
        }

        .action-btn {
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            border: none;
            margin-right: 0.5rem;
        }

        .action-kill {
            background: rgba(255, 71, 87, 0.1);
            color: var(--accent-red);
        }

        .action-kill:hover {
            background: var(--accent-red);
            color: white;
        }

        /* Config Panel (Strict Mode) */
        .config-panel {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .config-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }

        .config-item label {
            display: block;
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }

        .config-item input,
        .config-item select {
            width: 100%;
            padding: 0.75rem;
            background: var(--bg-hover);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 0.875rem;
        }

        /* Charts */
        .chart-container {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            height: 400px;
        }

        /* Documentation Sections */
        .doc-section {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
        }

        .doc-title {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
        }

        .doc-subtitle {
            font-size: 1.125rem;
            font-weight: 600;
            margin-top: 2rem;
            margin-bottom: 1rem;
            color: var(--accent-cyan);
        }

        .doc-content {
            line-height: 1.8;
            color: var(--text-secondary);
        }

        .doc-content ul {
            margin-left: 1.5rem;
            margin-top: 0.5rem;
        }

        .doc-content li {
            margin-bottom: 0.5rem;
        }

        .doc-highlight {
            background: linear-gradient(135deg, rgba(0, 217, 255, 0.1), rgba(0, 255, 136, 0.1));
            border-left: 3px solid var(--accent-cyan);
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 8px;
        }

        /* FAQ Accordion */
        .faq-item {
            background: var(--bg-hover);
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }

        .faq-question {
            padding: 1rem 1.5rem;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
        }

        .faq-question:hover {
            background: rgba(0, 217, 255, 0.05);
        }

        .faq-answer {
            padding: 0 1.5rem;
            max-height: 0;
            overflow: hidden;
            transition: all 0.3s ease;
            color: var(--text-secondary);
        }

        .faq-item.active .faq-answer {
            max-height: 500px;
            padding: 0 1.5rem 1.5rem;
        }

        .faq-item.active .faq-question {
            color: var(--accent-cyan);
        }

        /* Responsive */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }

            .main-container {
                margin-left: 0;
            }

            .mode-cards {
                grid-template-columns: 1fr;
            }
        }

        /* Animations */
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .slide-in {
            animation: slideIn 0.5s ease;
        }

        /* Loading Spinner */
        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--border-color);
            border-top-color: var(--accent-cyan);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Toast Notifications */
        .toast {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            padding: 1rem 1.5rem;
            background: var(--bg-card);
            border: 1px solid var(--accent-cyan);
            border-radius: 8px;
            color: var(--text-primary);
            font-weight: 500;
            z-index: 9999;
            transform: translateX(400px);
            transition: transform 0.3s ease;
        }

        .toast.show {
            transform: translateX(0);
        }
    </style>
</head>
<body>
    <!-- Mode Selection Screen -->
    <div class="mode-selection" id="modeSelection">
        <div class="mode-container">
            <div class="logo-container">
                <div class="logo-icon">
                    <i class="fas fa-eye"></i>
                </div>
                <div class="logo-text">DṚŚYA</div>
            </div>
            <h2 class="mode-title">Select Security Mode</h2>
            <div class="mode-cards">
                <div class="mode-card" onclick="selectMode('lenient')">
                    <div class="mode-icon">🛡️</div>
                    <div class="mode-name">Lenient Mode</div>
                    <div class="mode-description">Basic monitoring for everyday use</div>
                </div>
                <div class="mode-card" onclick="selectMode('strict')">
                    <div class="mode-icon">⚔️</div>
                    <div class="mode-name">Strict Mode</div>
                    <div class="mode-description">Advanced protection with premium features</div>
                </div>
            </div>
            <button class="continue-btn" id="continueBtn" disabled onclick="continueToDashboard()">
                Continue to Dashboard
            </button>
        </div>
    </div>

    <!-- Main Dashboard -->
    <div class="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">
                <i class="fas fa-eye"></i>
            </div>
            <div class="sidebar-title">DṚŚYA</div>
        </div>
        
        <div class="nav-section">
            <a class="nav-item active" onclick="showSection('dashboard')">
                <i class="fas fa-th-large"></i>
                <span>Dashboard</span>
            </a>
            <a class="nav-item" onclick="showSection('manual')">
                <i class="fas fa-book"></i>
                <span>User Manual</span>
            </a>
            <a class="nav-item" onclick="showSection('faq')">
                <i class="fas fa-question-circle"></i>
                <span>FAQs</span>
            </a>
            <a class="nav-item" onclick="window.open('https://nvd.nist.gov/vuln/search', '_blank')">
                <i class="fas fa-search"></i>
                <span>NVD Search</span>
            </a>
        </div>
    </div>

    <div class="main-container">
        <div class="header">
            <h1 class="header-title">SECURITY MONITOR</h1>
            <div class="header-controls">
                <div class="mode-badge" id="modeBadge">Lenient Mode</div>
                <button class="theme-toggle" onclick="toggleTheme()">
                    <i class="fas fa-moon" id="themeIcon"></i>
                </button>
            </div>
        </div>

        <div class="content">
            <!-- Dashboard Section -->
            <div class="content-section active" id="dashboard">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Total</div>
                        <div class="stat-value" style="color: var(--accent-cyan);" id="totalThreats">0</div>
                        <div class="stat-change">Active Threats</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">High</div>
                        <div class="stat-value" style="color: var(--accent-red);" id="highPriority">0</div>
                        <div class="stat-change">Critical Priority</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Medium</div>
                        <div class="stat-value" style="color: var(--accent-orange);" id="mediumPriority">0</div>
                        <div class="stat-change">Medium Priority</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Low</div>
                        <div class="stat-value" style="color: var(--accent-green);" id="lowPriority">0</div>
                        <div class="stat-change">Low Priority</div>
                    </div>
                </div>

                <div class="control-panel">
                    <div class="control-header">
                        <div class="control-title">Status</div>
                        <div class="status-badge status-inactive" id="monitorStatus">
                            <i class="fas fa-circle pulse"></i>
                            <span>Inactive</span>
                        </div>
                    </div>
                    <div class="control-buttons">
                        <button class="btn btn-primary" onclick="startMonitoring()">
                            <i class="fas fa-play"></i> Start
                        </button>
                        <button class="btn btn-danger" onclick="stopMonitoring()">
                            <i class="fas fa-stop"></i> Stop
                        </button>
                        <button class="btn btn-secondary" onclick="killAll()">
                            Kill
                        </button>
                    </div>
                    <div style="margin-top: 1rem;">
                        <label style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-secondary);">
                            <input type="checkbox" id="autoKillCheck" style="width: 18px; height: 18px;">
                            <span>Auto-kill after scan</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-secondary); margin-top: 0.5rem;">
                            <input type="checkbox" id="manualKillCheck" checked style="width: 18px; height: 18px;">
                            <span>Manual kill option</span>
                        </label>
                    </div>
                </div>

                <!-- Configuration Panel (Strict Mode Only) -->
                <div class="config-panel" id="configPanel" style="display: none;">
                    <h3 style="margin-bottom: 1rem;">Advanced Configuration</h3>
                    <div class="config-grid">
                        <div class="config-item">
                            <label>Auto-Kill High Priority</label>
                            <select id="autoKillSelect">
                                <option value="enabled">Enabled</option>
                                <option value="disabled">Disabled</option>
                            </select>
                        </div>
                        <div class="config-item">
                            <label>Refresh Interval</label>
                            <select id="refreshInterval">
                                <option value="5">5 seconds</option>
                                <option value="10" selected>10 seconds</option>
                                <option value="30">30 seconds</option>
                            </select>
                        </div>
                        <div class="config-item">
                            <label>Safe Text (Whitelist)</label>
                            <input type="text" id="whitelistInput" placeholder="Enter safe processes...">
                        </div>
                    </div>
                </div>

                <!-- Charts Section -->
                <div class="chart-container" style="display: none;" id="chartsSection">
                    <canvas id="threatChart"></canvas>
                </div>

                <!-- Threat Detection Matrix -->
                <div class="threat-section">
                    <div class="threat-header">
                        <h3>Detected Threats</h3>
                        <span style="color: var(--text-muted); font-size: 0.875rem;">
                            Reference: NVD Database | Last scan: <span id="lastScan">Never</span>
                        </span>
                    </div>
                    <table class="threat-table">
                        <thead>
                            <tr>
                                <th>PID</th>
                                <th>NAME</th>
                                <th>TYPE</th>
                                <th>PRIORITY</th>
                                <th>ACCESS</th>
                                <th>ACTION</th>
                            </tr>
                        </thead>
                        <tbody id="threatTableBody">
                            <tr>
                                <td colspan="6" style="text-align: center; padding: 3rem; color: var(--text-muted);">
                                    No threats detected
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- User Manual Section -->
            <div class="content-section" id="manual">
                <div class="doc-section">
                    <h1 class="doc-title">User Manual</h1>
                    <p style="color: var(--text-secondary); margin-bottom: 2rem;">Complete guide to using the Security Monitoring System</p>
                    
                    <div class="doc-highlight">
                        <h2 class="doc-subtitle">System Overview</h2>
                        <div class="doc-content">
                            <p>The <strong>Security Monitoring System</strong> is an advanced, real-time security platform designed to detect and mitigate:</p>
                            <ul>
                                <li><strong>Keylogging attempts</strong> - Unauthorized capture of keystrokes</li>
                                <li><strong>Sensor snooping attempts</strong> - Unauthorized access to microphone, camera, or Bluetooth devices</li>
                            </ul>
                            <p>This system operates in two adaptable monitoring modes — <strong>Strict Mode</strong> for maximum protection and <strong>Lenient Mode</strong> for essential monitoring with minimal false positives.</p>
                        </div>
                    </div>

                    <div class="doc-highlight">
                        <h2 class="doc-subtitle">Monitoring Modes</h2>
                        <div class="doc-content">
                            <h3 style="color: var(--accent-red); margin-top: 1rem;">Strict Mode (Advanced Security)</h3>
                            <p>Strict Mode provides maximum security for high-risk or sensitive systems. Features include:</p>
                            <ul>
                                <li>Configurable monitoring intervals for tailored performance</li>
                                <li>Enhanced detection algorithms for stealth-based threats</li>
                                <li>Auto-kill functionality for instant termination</li>
                                <li>Whitelist management for trusted applications</li>
                            </ul>
                            
                            <h3 style="color: var(--accent-green); margin-top: 1rem;">Lenient Mode (Basic Security)</h3>
                            <p>Lenient Mode focuses on essential monitoring in low-risk environments. Features include:</p>
                            <ul>
                                <li>Fixed 10-second monitoring intervals</li>
                                <li>Basic detection capabilities</li>
                                <li>Manual termination requiring user review</li>
                                <li>Simplified interface for efficient navigation</li>
                            </ul>
                        </div>
                    </div>

                    <div class="doc-highlight">
                        <h2 class="doc-subtitle">Process ID (PID) Analysis</h2>
                        <div class="doc-content">
                            <p>Every active process is assigned a Process ID (PID), enabling precise tracking:</p>
                            <ul>
                                <li><strong>PID</strong> - Unique identifier for the process</li>
                                <li><strong>Name</strong> - Official name of the application</li>
                                <li><strong>Type</strong> - Category of activity (keylogger, mic access, etc.)</li>
                                <li><strong>Priority</strong> - Severity rating (High/Medium/Low)</li>
                                <li><strong>Access</strong> - Specific hardware accessed</li>
                                <li><strong>Action</strong> - User response options</li>
                            </ul>
                        </div>
                    </div>

                    <div class="doc-highlight">
                        <h2 class="doc-subtitle">Access Column Details</h2>
                        <div class="doc-content">
                            <p>The Access column indicates the specific system resource being accessed:</p>
                            <ul>
                                <li><strong>Keyboard</strong> - Possible keylogging attempt</li>
                                <li><strong>Microphone</strong> - Possible audio surveillance</li>
                                <li><strong>Camera</strong> - Possible video surveillance</li>
                                <li><strong>Bluetooth</strong> - Potential wireless data leakage</li>
                            </ul>
                        </div>
                    </div>

                    <div class="doc-highlight">
                        <h2 class="doc-subtitle">Dashboard Controls</h2>
                        <div class="doc-content">
                            <h3>Primary Indicators:</h3>
                            <ul>
                                <li><strong>Total</strong> - Number of threats detected</li>
                                <li><strong>High/Medium/Low</strong> - Count by severity</li>
                            </ul>
                            <h3>Control Buttons:</h3>
                            <ul>
                                <li><strong>Start</strong> - Initiates real-time monitoring</li>
                                <li><strong>Stop</strong> - Halts monitoring</li>
                                <li><strong>Kill</strong> - Terminate selected processes</li>
                            </ul>
                            <h3>Status Panel:</h3>
                            <ul>
                                <li><strong>Active/Inactive</strong> - Current system state</li>
                                <li><strong>Last Scan</strong> - Timestamp of recent scan</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <!-- FAQ Section -->
            <div class="content-section" id="faq">
                <div class="doc-section">
                    <h1 class="doc-title">Frequently Asked Questions</h1>
                    <p style="color: var(--text-secondary); margin-bottom: 2rem;">Find answers to common questions about the Security Monitoring System</p>
                    
                    <div class="faq-item">
                        <div class="faq-question" onclick="toggleFAQ(this)">
                            What types of threats does the system detect?
                            <i class="fas fa-chevron-down"></i>
                        </div>
                        <div class="faq-answer">
                            The system is designed to identify and flag keylogging attempts, unauthorized access to sensors (microphone, camera, Bluetooth), and other suspicious processes attempting to interact with sensitive resources.
                        </div>
                    </div>

                    <div class="faq-item">
                        <div class="faq-question" onclick="toggleFAQ(this)">
                            How does the system differentiate between legitimate and malicious processes?
                            <i class="fas fa-chevron-down"></i>
                        </div>
                        <div class="faq-answer">
                            The detection engine uses process behavior analysis, resource access patterns, and user-defined whitelists to distinguish between trusted applications and potential threats.
                        </div>
                    </div>

                    <div class="faq-item">
                        <div class="faq-question" onclick="toggleFAQ(this)">
                            Will the system slow down my computer?
                            <i class="fas fa-chevron-down"></i>
                        </div>
                        <div class="faq-answer">
                            No, the system is designed for minimal performance impact. Lenient Mode runs lightweight scans every 10 seconds, while Strict Mode allows custom intervals to balance performance and security needs.
                        </div>
                    </div>

                    <div class="faq-item">
                        <div class="faq-question" onclick="toggleFAQ(this)">
                            Can I customize which processes are flagged?
                            <i class="fas fa-chevron-down"></i>
                        </div>
                        <div class="faq-answer">
                            Yes, the Whitelist Management feature allows you to mark specific applications as trusted, ensuring they are not flagged in future scans.
                        </div>
                    </div>

                    <div class="faq-item">
                        <div class="faq-question" onclick="toggleFAQ(this)">
                            How frequently does the system scan for threats?
                            <i class="fas fa-chevron-down"></i>
                        </div>
                        <div class="faq-answer">
                            <ul>
                                <li><strong>Lenient Mode</strong> scans every 10 seconds</li>
                                <li><strong>Strict Mode</strong> has configurable scan intervals that can be adjusted for higher responsiveness or lower system impact</li>
                            </ul>
                        </div>
                    </div>

                    <div class="faq-item">
                        <div class="faq-question" onclick="toggleFAQ(this)">
                            Does the system automatically remove threats?
                            <i class="fas fa-chevron-down"></i>
                        </div>
                        <div class="faq-answer">
                            In <strong>Strict Mode</strong>, confirmed high-risk processes are terminated automatically via the Auto-Kill feature. In <strong>Lenient Mode</strong>, termination requires manual user approval.
                        </div>
                    </div>

                    <div class="faq-item">
                        <div class="faq-question" onclick="toggleFAQ(this)">
                            What happens if I accidentally whitelist a malicious process?
                            <i class="fas fa-chevron-down"></i>
                        </div>
                        <div class="faq-answer">
                            You can easily remove a process from the whitelist at any time. The system will resume monitoring it in subsequent scans.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast Notification -->
    <div class="toast" id="toast"></div>

    <script>
        let socket = io();
        let selectedMode = null;
        let currentMode = 'lenient';
        let currentTheme = 'dark';
        let isMonitoring = false;
        let startTime = null;
        let threatChart = null;

        // Mode Selection
        function selectMode(mode) {
            selectedMode = mode;
            document.querySelectorAll('.mode-card').forEach(card => card.classList.remove('selected'));
            event.target.closest('.mode-card').classList.add('selected');
            document.getElementById('continueBtn').disabled = false;
        }

        function continueToDashboard() {
            if (!selectedMode) return;
            currentMode = selectedMode;
            document.getElementById('modeSelection').classList.add('hidden');
            document.getElementById('modeBadge').textContent = currentMode === 'strict' ? 'Strict Mode' : 'Lenient Mode';
            
            // Show/hide strict mode features
            if (currentMode === 'strict') {
                document.getElementById('configPanel').style.display = 'block';
                document.getElementById('chartsSection').style.display = 'block';
                initChart();
            }
            
            showToast(`Initialized in ${currentMode} mode`);
        }

        // Theme Toggle
        function toggleTheme() {
            const body = document.body;
            const icon = document.getElementById('themeIcon');
            
            if (body.hasAttribute('data-theme')) {
                body.removeAttribute('data-theme');
                icon.className = 'fas fa-moon';
                currentTheme = 'dark';
            } else {
                body.setAttribute('data-theme', 'light');
                icon.className = 'fas fa-sun';
                currentTheme = 'light';
            }
            
            showToast(`Switched to ${currentTheme} theme`);
        }

        // Navigation
        function showSection(section) {
            // Update nav items
            document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
            event.target.closest('.nav-item').classList.add('active');
            
            // Show/hide sections
            document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
            document.getElementById(section).classList.add('active');
        }

        // FAQ Toggle
        function toggleFAQ(element) {
            const parent = element.parentElement;
            parent.classList.toggle('active');
        }

        // Socket.IO handlers
        socket.on('connect', () => {
            console.log('Connected to Dṛśya server');
        });

        socket.on('threat_update', (data) => {
            updateDashboard(data);
        });

        function updateDashboard(data) {
            document.getElementById('totalThreats').textContent = data.total || 0;
            document.getElementById('highPriority').textContent = data.high_priority || 0;
            document.getElementById('mediumPriority').textContent = data.medium_priority || 0;
            document.getElementById('lowPriority').textContent = data.low_priority || 0;
            document.getElementById('lastScan').textContent = new Date().toLocaleTimeString();
            
            updateThreatsTable(data.threats || []);
            
            if (threatChart && currentMode === 'strict') {
                updateChart(data);
            }
        }

        function updateThreatsTable(threats) {
            const tbody = document.getElementById('threatTableBody');
            
            if (!threats || threats.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 3rem; color: var(--text-muted);">No threats detected</td></tr>';
                return;
            }

            tbody.innerHTML = threats.map(t => `
                <tr>
                    <td>${t.pid}</td>
                    <td><strong>${t.name}</strong></td>
                    <td>${t.type}</td>
                    <td><span class="priority-badge priority-${t.priority.toLowerCase()}">${t.priority}</span></td>
                    <td>${t.resources ? t.resources.join(', ') : 'Yes'}</td>
                    <td>
                        <button class="action-btn action-kill" onclick="killProcess(${t.pid})">
                            KILL
                        </button>
                    </td>
                </tr>
            `).join('');
        }

        // Monitoring Controls
        function startMonitoring() {
            const autoKill = currentMode === 'strict' && document.getElementById('autoKillSelect')?.value === 'enabled';
            const interval = currentMode === 'strict' ? document.getElementById('refreshInterval')?.value : 10;
            const whitelist = currentMode === 'strict' ? document.getElementById('whitelistInput')?.value : '';

            fetch('/api/start_monitoring', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    mode: currentMode,
                    autoKill: autoKill || document.getElementById('autoKillCheck').checked,
                    refreshInterval: interval,
                    whitelist: whitelist
                })
            }).then(response => response.json())
            .then(data => {
                if (data.status === 'started') {
                    isMonitoring = true;
                    startTime = Date.now();
                    document.getElementById('monitorStatus').className = 'status-badge status-active';
                    document.getElementById('monitorStatus').innerHTML = '<i class="fas fa-circle pulse"></i> <span>Active</span>';
                    showToast('Monitoring started');
                }
            });
        }

        function stopMonitoring() {
            fetch('/api/stop_monitoring', {method: 'POST'})
                .then(() => {
                    isMonitoring = false;
                    document.getElementById('monitorStatus').className = 'status-badge status-inactive';
                    document.getElementById('monitorStatus').innerHTML = '<i class="fas fa-circle"></i> <span>Inactive</span>';
                    showToast('Monitoring stopped');
                });
        }

        function killProcess(pid) {
            if (confirm(`Terminate process ${pid}?`)) {
                fetch('/api/kill_process', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({pid: pid})
                }).then(() => showToast(`Process ${pid} terminated`));
            }
        }

        function killAll() {
            if (confirm('Terminate all detected threats?')) {
                showToast('Terminating all threats...');
            }
        }

        // Chart initialization (Strict mode)
        function initChart() {
            const ctx = document.getElementById('threatChart')?.getContext('2d');
            if (!ctx) return;
            
            threatChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Threats Detected',
                        data: [],
                        borderColor: '#00d9ff',
                        backgroundColor: 'rgba(0, 217, 255, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#a8b2d1'
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: '#a8b2d1'
                            },
                            grid: {
                                color: '#2a3f5f'
                            }
                        },
                        x: {
                            ticks: {
                                color: '#a8b2d1'
                            },
                            grid: {
                                color: '#2a3f5f'
                            }
                        }
                    }
                }
            });
        }

        function updateChart(data) {
            if (!threatChart) return;
            
            const time = new Date().toLocaleTimeString();
            threatChart.data.labels.push(time);
            threatChart.data.datasets[0].data.push(data.total);
            
            if (threatChart.data.labels.length > 10) {
                threatChart.data.labels.shift();
                threatChart.data.datasets[0].data.shift();
            }
            
            threatChart.update();
        }

        // Toast notifications
        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.classList.add('show');
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            // Check URL params
            const urlParams = new URLSearchParams(window.location.search);
            const mode = urlParams.get('mode');
            
            if (mode) {
                selectedMode = mode;
                continueToDashboard();
            }
        });
    </script>
</body>
</html>'''

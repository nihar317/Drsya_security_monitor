#!/bin/bash
# Dṛśya Desktop Integration Setup

echo "🛡️ Setting up Dṛśya Desktop Integration..."

# Create .desktop file for Linux
cat > drsya.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Dṛśya Security Monitor
Comment=Ultimate Security Monitoring Tool
Exec=python3 /path/to/your/drsya_app.py
Icon=/path/to/your/drsya_icon.png
Terminal=false
Categories=Security;System;Monitor;
StartupNotify=true
EOF

# Create Windows batch file
cat > drsya.bat << 'EOF'
@echo off
title Dṛśya Security Monitor
echo 🛡️ Starting Dṛśya Security Monitor...
python drsya_app.py
pause
EOF

# Create launch script for Linux/Mac
cat > drsya_launch.sh << 'EOF'
#!/bin/bash
echo "🛡️ Starting Dṛśya Security Monitor..."
cd "$(dirname "$0")"
python3 drsya_app.py
EOF

chmod +x drsya_launch.sh

echo "✅ Desktop integration files created:"
echo "   • drsya.desktop (Linux desktop entry)"
echo "   • drsya.bat (Windows batch file)"
echo "   • drsya_launch.sh (Linux/Mac launcher)"
echo ""
echo "📝 To install on Linux:"
echo "   1. Update paths in drsya.desktop"
echo "   2. Copy to ~/.local/share/applications/"
echo "   3. Run: update-desktop-database ~/.local/share/applications/"
echo ""
echo "🚀 Ready to launch!"

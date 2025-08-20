#!/bin/bash

echo "🛡️  Dṛśya Security Monitor - Quick Start"
echo "========================================"
echo ""
echo "Select mode:"
echo "1) 🛡️  Lenient Mode (Safe for daily use)"
echo "2) ⚔️  Strict Mode (Enhanced security)" 
echo "3) 🌐 Web Dashboard Only"
echo "4) ❌ Exit"
echo ""

while true; do
    read -p "Enter choice (1-4): " choice
    case $choice in
        1)
            echo "🚀 Starting Lenient Mode..."
            cd "$(dirname "$0")"
            source venv/bin/activate 2>/dev/null || echo "⚠️  Virtual env not found, using system Python"
            python3 drsya_monitor.py --lenient
            break
            ;;
        2)
            echo "🚀 Starting Strict Mode..."
            cd "$(dirname "$0")"
            source venv/bin/activate 2>/dev/null || echo "⚠️  Virtual env not found, using system Python"
            python3 drsya_monitor.py --strict
            break
            ;;
        3)
            echo "🌐 Opening web dashboard..."
            python3 -c "import webbrowser; webbrowser.open('http://localhost:5000')"
            echo "📝 Make sure Drsya is running in another terminal!"
            break
            ;;
        4)
            echo "👋 Goodbye!"
            exit 0
            ;;
        *)
            echo "❌ Invalid choice. Please enter 1, 2, 3, or 4."
            ;;
    esac
done

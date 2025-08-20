#!/bin/bash
clear
echo "🛡️ DṚŚYA LAUNCHER"
echo "================="
echo "1) Lenient Mode"
echo "2) Strict Mode"
read -p "Choice: " choice

if [ "$choice" = "2" ]; then
    python3 drsya_monitor.py --strict
else
    python3 drsya_monitor.py --lenient
fi

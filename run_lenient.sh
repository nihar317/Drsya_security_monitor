#!/bin/bash
echo "🛡️  Starting Drsya in Lenient Mode..."
cd "$(dirname "$0")"
source venv/bin/activate 2>/dev/null || echo "⚠️  Using system Python"
python3 drsya_monitor.py --lenient

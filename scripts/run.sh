#!/usr/bin/env bash
# Start the app on http://127.0.0.1:5000  (PORT=5001 ./scripts/run.sh to change the port)
cd "$(dirname "$0")/.." && exec python3 vapt_app.py

#!/usr/bin/env bash
# One-click launcher: sets up a venv (first run only), installs deps,
# starts the local server, and opens the UI in your browser.
set -e
cd "$(dirname "$0")"

if [ ! -d venv ]; then
  echo "Setting up virtual environment (first run only)..."
  python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r requirements.txt
python app.py

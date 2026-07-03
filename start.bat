@echo off
REM One-click launcher: sets up a venv (first run only), installs deps,
REM starts the local server, and opens the UI in your browser.
cd /d "%~dp0"

if not exist venv (
    echo Setting up virtual environment first run only...
    python -m venv venv
)

call venv\Scripts\activate
pip install -q -r requirements.txt
python app.py

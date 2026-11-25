#!/bin/bash
# Double-click on a Mac to start Capsight Capture. It asks for your password because capturing needs admin rights.
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is not installed. Get it from https://www.python.org/downloads/ and run this again."; read -r -p "Press Enter to close."; exit 1
fi
if ! python3 -c "import scapy" 2>/dev/null; then
  echo "Installing scapy (one time)..."; python3 -m pip install --user --quiet scapy || { read -r -p "Could not install scapy. Press Enter to close."; exit 1; }
fi
SITE="$(python3 -m site --user-site)"
echo "Capsight Capture needs admin rights to read network traffic. Enter your Mac password if asked."
sudo PYTHONPATH="$SITE${PYTHONPATH:+:$PYTHONPATH}" python3 capsight_capture.py "$@"

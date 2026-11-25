@echo off
rem Double-click on Windows to start Capsight Capture. Needs Npcap (https://npcap.com) and admin rights.
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -Command "Start-Process '%~f0' -Verb RunAs"
  exit /b
)
where py >nul 2>&1 && (set PY=py) || (set PY=python)
%PY% -c "import scapy" 2>nul || %PY% -m pip install --quiet scapy
%PY% capsight_capture.py %*
pause

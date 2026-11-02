@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" "tools\launch_netpulse.py" %*
  goto :done
)
where py >nul 2>nul
if not errorlevel 1 (
  py -3.12 "tools\launch_netpulse.py" %*
  goto :done
)
python "tools\launch_netpulse.py" %*
:done
if errorlevel 1 pause
endlocal

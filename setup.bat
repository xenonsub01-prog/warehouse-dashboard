@echo off
cd /d %~dp0
echo === Creating virtual environment ===
python -m venv venv
if exist venv\Scripts\activate.bat (
  call venv\Scripts\activate
) else (
  echo Failed to create venv. Ensure Python 3.10+ is installed and on PATH.
  pause
  exit /b 1
)
python -m pip install --upgrade pip
pip install -r requirements.txt
if not exist .env (
  set RAND=%RANDOM%%RANDOM%%RANDOM%
  echo DEMO_SECRET=%RAND%> .env
  set OK=%RANDOM%%RANDOM%
  echo OWNER_KEY=%OK%>> .env
  echo BASE_URL=http://localhost:8501/>> .env
  echo Created .env with DEMO_SECRET, OWNER_KEY, BASE_URL.
)
echo Setup complete.
pause

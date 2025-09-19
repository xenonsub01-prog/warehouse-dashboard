@echo off
cd /d %~dp0
if not exist venv\Scripts\activate.bat (
  echo Please run setup.bat first.
  pause
  exit /b 1
)
if exist .env (
  for /f "usebackq tokens=1,2 delims==" %%a in (".env") do set %%a=%%b
)
call venv\Scripts\activate
set DATA_PATH=data\orders.csv
set LOG_PATH=data\log.csv
set LOOKUPS_PATH=data\lookups.csv
set TOKENS_DIR=tokens
start "" http://localhost:8502/?admin=%OWNER_KEY%
streamlit run app.py --server.port=8502

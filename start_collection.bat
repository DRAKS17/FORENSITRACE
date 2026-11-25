@echo off
cd /d "C:\mini\ForensiTrace"
set PYTHONPATH=C:\mini\ForensiTrace

echo Starting ForensiTrace Ingestion Backend...
start "ForensiTrace-Backend" /b python -m backend.app.main

timeout /t 2 /nobreak >nul

echo Starting ForensiTrace Endpoint Agent...
start "ForensiTrace-Agent" /b python -m agent.main

echo ForensiTrace data collection started in background.

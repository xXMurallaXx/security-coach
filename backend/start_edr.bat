@echo off
cd C:\Users\Frana\security-coach\backend
C:\Users\Frana\security-coach\venv\Scripts\uvicorn.exe app.main:app --host 0.0.0.0 --port 8001 > SOC_log.txt 2>&1
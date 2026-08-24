@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
if exist "FirebaseSecurityAuditor.exe" (
  "FirebaseSecurityAuditor.exe" wizard
) else if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m firebase_security_auditor wizard
) else (
  echo 실행 파일과 .venv가 없습니다. PowerShell에서 .\설치.ps1을 먼저 실행하세요.
  pause
  exit /b 2
)
set RC=%ERRORLEVEL%
echo 종료 코드: %RC%
if not "%RC%"=="0" pause
exit /b %RC%


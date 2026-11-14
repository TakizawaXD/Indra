@echo off
REM ============================================================================
REM  INDRA INFINITY SECURITY - SCRIPT DE INICIO (WINDOWS)
REM  Creador: Takizawa | Para: Indra
REM ============================================================================

title INDRA INFINITY SECURITY - TAKIZAWA
cd /d "%~dp0"
chcp 65001 >nul
set PYTHONUTF8=1

echo [*] Verificando entorno de Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] Error: Python no esta instalado o no se encuentra en el PATH.
    pause
    exit /b 1
)

echo [*] Iniciando INDRA INFINITY SECURITY...
echo [*] Servidor y panel local en http://127.0.0.1:8000
echo [*] Presiona Ctrl+C para detener el servicio.
echo.

python -m backend.main

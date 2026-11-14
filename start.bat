@echo off
REM ============================================================================
REM  GOJO INFINITY SECURITY (INDEFINIDO) - SCRIPT DE INICIO (WINDOWS)
REM  Creador: Takizawa | Para: Indra
REM ============================================================================

title GOJO INFINITY SECURITY - INDRA
cd /d "%~dp0"

echo [*] Verificando entorno de Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] Error: Python no esta instalado o no se encuentra en el PATH.
    pause
    exit /b 1
)

echo [*] Inicializando base de datos y esquemas...
python -c "from backend.database import init_db; init_db()"

echo [*] Iniciando servidor y panel local en http://127.0.0.1:8000 ...
echo [*] Presiona Ctrl+C para detener el servicio.
echo.

python -m backend.main

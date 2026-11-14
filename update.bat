@echo off
REM ============================================================================
REM  INDRA INFINITY SECURITY - ACTUALIZADOR AUTOMATICO (WINDOWS)
REM  Creador: Takizawa | Para: Indra
REM ============================================================================

title INDRA INFINITY SECURITY - ACTUALIZADOR
cd /d "%~dp0"
chcp 65001 >nul
set PYTHONUTF8=1

echo ============================================================================
echo  [*] COMPROBANDO ACTUALIZACIONES DESDE GITHUB (TakizawaXD/Indra)
echo ============================================================================
echo.

echo [*] Sincronizando repositorio oficial con git pull...
git pull origin main
if errorlevel 1 (
    echo.
    echo [-] No se pudo conectar a GitHub o modo offline activo.
    echo [*] Manteniendo la version local sin modificaciones.
) else (
    echo.
    echo [+] Codigo fuente actualizado al ultimo commit.
)

echo.
echo [*] Actualizando dependencias de Python (requirements.txt)...
python -m pip install --upgrade pip setuptools wheel --quiet
python -m pip install -r requirements.txt --quiet
echo [+] Dependencias verificadas y al dia.

echo.
echo ============================================================================
echo  [+] SISTEMA ACTUALIZADO EXITOSAMENTE PARA INDRA
echo ============================================================================
echo.
pause

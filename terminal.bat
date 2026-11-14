@echo off
REM ============================================================================
REM  INDRA INFINITY SECURITY - TERMINAL INTERACTIVA (WINDOWS)
REM  Creador: Takizawa | Para: Indra
REM ============================================================================

title INDRA TERMINAL - TAKIZAWA
cd /d "%~dp0"
chcp 65001 >nul
set PYTHONUTF8=1

python -m terminal.shell

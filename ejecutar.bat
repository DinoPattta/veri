@echo off
color 0A

REM Cambiar a la carpeta donde está este script
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] REQUIERE PERMISOS DE ADMINISTRADOR
    echo.
    echo Solucion: Click DERECHO > "Ejecutar como administrador"
    echo.
    pause
    exit /b 1
)

python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] Python no esta instalado
    echo.
    echo Descarga desde: https://www.python.org/
    echo IMPORTANTE: Marca "Add Python to PATH" durante la instalacion
    echo.
    pause
    exit /b 1
)

python veri.py
pause

@echo off
setlocal enabledelayedexpansion

REM ====================================================
REM Универсальный лаунчер для запуска ЛЮБОГО Python скрипта в виртуальном окружении
REM Использование: run_in_venv.bat <python_script> [аргументы...]
REM ====================================================

REM Получаем директории
set "CALLER_DIR=%CD%"
set "BAT_DIR=%~dp0"
set "BAT_DIR=%BAT_DIR:~0,-1%"

REM Параметры
set "VENV_DIR=%BAT_DIR%\.venv"
set "REQUIREMENTS_FILE=%BAT_DIR%\requirements.txt"
set "PYTHON_SCRIPT=%~1"

if "%PYTHON_SCRIPT%"=="" (
    echo [ERROR] Usage: %~nx0 ^<python_script^> [arguments...]
    echo [ERROR] Example: %~nx0 cs2_to_json_exporter.py --indent 4
    exit /b 1
)

echo [*] ========================================
echo [*] Universal Venv Launcher
echo [*] ========================================
echo [*] Caller directory: %CALLER_DIR%
echo [*] Script directory: %BAT_DIR%
echo [*] Target script: %PYTHON_SCRIPT%

REM Сохраняем все аргументы кроме первого
set "SCRIPT_ARGS="
:loop
shift
if "%~1"=="" goto continue
set "SCRIPT_ARGS=%SCRIPT_ARGS% %~1"
goto loop
:continue

echo [*] Arguments: %SCRIPT_ARGS%

REM Проверяем существование виртуального окружения
if not exist "%VENV_DIR%" (
    echo [*] Virtual environment not found. Creating new one...
    python -m venv "%VENV_DIR%" >nul
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        exit /b 1
    )
    echo [✓] Virtual environment created: %VENV_DIR%
    
    REM Если есть requirements, устанавливаем зависимости
    if exist "%REQUIREMENTS_FILE%" (
        echo [*] Installing requirements from %REQUIREMENTS_FILE%...
        "%VENV_DIR%\Scripts\pip.exe" install -r "%REQUIREMENTS_FILE%" -q
        if errorlevel 1 (
            echo [ERROR] Failed to install requirements
            exit /b 1
        )
        echo [✓] Requirements installed successfully
    )
) else (
    echo [*] Using existing virtual environment: %VENV_DIR%
)

REM Проверяем существование целевого скрипта
set "FULL_SCRIPT_PATH=%CALLER_DIR%\%PYTHON_SCRIPT%"
if not exist "%FULL_SCRIPT_PATH%" (
    echo [ERROR] Script not found: %FULL_SCRIPT_PATH%
    exit /b 1
)

REM Запускаем скрипт в виртуальном окружении
echo [*] ========================================
echo [*] Running script in virtual environment...
echo [*] Command: python %PYTHON_SCRIPT%%SCRIPT_ARGS%
echo [*] ========================================

pushd "%CALLER_DIR%"
"%VENV_DIR%\Scripts\python.exe" "%PYTHON_SCRIPT%" %SCRIPT_ARGS%
set "EXIT_CODE=!errorlevel!"
popd

echo [*] ========================================
if !EXIT_CODE! == 0 (
    echo [✓] Script completed successfully
) else (
    echo [ERROR] Script failed with code: !EXIT_CODE!
)
echo [*] ========================================

exit /b !EXIT_CODE!
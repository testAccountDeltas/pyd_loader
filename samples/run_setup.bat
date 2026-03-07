@echo off
setlocal enabledelayedexpansion

REM ====================================================
REM Специализированный лаунчер для setup.py
REM Автоматически находит setup.py и использует правильные пути
REM ====================================================

REM Получаем директории
set "CALLER_DIR=%CD%"
set "BAT_DIR=%~dp0"
set "BAT_DIR=%BAT_DIR:~0,-1%"

REM Параметры
set "VENV_DIR=%BAT_DIR%\.venv"
set "REQUIREMENTS_FILE=%BAT_DIR%\requirements.txt"

REM Определяем правильный путь к setup.py
set "SETUP_PATH="

if exist "%CALLER_DIR%\setup.py" (
    REM setup.py в текущей директории
    set "WORK_DIR=%CALLER_DIR%"
    set "SETUP_PATH=setup.py"
    echo [*] Found setup.py in current directory
) else if exist "%BAT_DIR%\setup.py" (
    REM setup.py в директории с батником
    set "WORK_DIR=%BAT_DIR%"
    set "SETUP_PATH=setup.py"
    echo [*] Found setup.py in script directory
) else if exist "%BAT_DIR%\..\setup.py" (
    REM setup.py на уровень выше батника
    for %%i in ("%BAT_DIR%\..") do set "WORK_DIR=%%~fi"
    set "SETUP_PATH=setup.py"
    echo [*] Found setup.py in parent directory: !WORK_DIR!
) else if exist "%BAT_DIR%\..\..\setup.py" (
    REM setup.py на два уровня выше батника
    for %%i in ("%BAT_DIR%\..\..") do set "WORK_DIR=%%~fi"
    set "SETUP_PATH=setup.py"
    echo [*] Found setup.py two levels up: !WORK_DIR!
) else (
    echo [ERROR] Could not find setup.py
    echo [ERROR] Searched in:
    echo [ERROR]   %CALLER_DIR%\setup.py
    echo [ERROR]   %BAT_DIR%\setup.py
    echo [ERROR]   %BAT_DIR%\..\setup.py
    echo [ERROR]   %BAT_DIR%\..\..\setup.py
    exit /b 1
)

echo [*] ========================================
echo [*] Setup.py Launcher
echo [*] ========================================
echo [*] Current directory: %CALLER_DIR%
echo [*] Script directory: %BAT_DIR%
echo [*] Working directory: !WORK_DIR!
echo [*] Setup.py path: !WORK_DIR!\!SETUP_PATH!
echo [*] Arguments: %*

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

REM Запускаем setup.py
echo [*] ========================================
echo [*] Running setup.py in virtual environment...
echo [*] ========================================

REM Переходим в рабочую директорию и запускаем setup.py
pushd "!WORK_DIR!"
echo [*] Now in: %CD%
echo [*] Running: "%VENV_DIR%\Scripts\python.exe" !SETUP_PATH! %*
"%VENV_DIR%\Scripts\python.exe" !SETUP_PATH! --launcher-dir="%CALLER_DIR%" %*
set "EXIT_CODE=!errorlevel!"
popd

echo [*] ========================================
if !EXIT_CODE! == 0 (
    echo [✓] Setup completed successfully
) else (
    echo [ERROR] Setup failed with code: !EXIT_CODE!
)
echo [*] ========================================

exit /b !EXIT_CODE!
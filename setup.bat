@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   Secure Cloud File Sharing System -- Windows Setup
echo ============================================================
echo.

REM ----------------------------------------------------------------
REM 1. Create virtual environment
REM ----------------------------------------------------------------
echo [1/5] Creating virtual environment (venv) ...
if exist venv\ (
    echo        venv\ already exists -- skipping creation.
) else (
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment.
        echo        Make sure Python 3.10+ is installed and on PATH.
        pause
        exit /b 1
    )
    echo        Virtual environment created.
)

REM ----------------------------------------------------------------
REM 2. Install dependencies
REM ----------------------------------------------------------------
echo.
echo [2/5] Installing Python dependencies from requirements.txt ...
if not exist requirements.txt (
    echo ERROR: requirements.txt not found.
    pause
    exit /b 1
)
venv\Scripts\pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: pip install failed. Check requirements.txt and your internet connection.
    pause
    exit /b 1
)
echo        Dependencies installed.

REM ----------------------------------------------------------------
REM 3. Create uploads/ directory
REM ----------------------------------------------------------------
echo.
echo [3/5] Creating uploads\ directory ...
if not exist uploads\ (
    mkdir uploads
    echo        uploads\ directory created.
) else (
    echo        uploads\ already exists -- skipping.
)

REM ----------------------------------------------------------------
REM 4. Copy .env.example to .env
REM ----------------------------------------------------------------
echo.
echo [4/5] Setting up .env configuration ...
if exist .env (
    echo        .env already exists -- not overwriting.
) else (
    if exist .env.example (
        copy .env.example .env >nul
        echo        .env created from .env.example.
        echo        IMPORTANT: Edit .env and set strong SECRET_KEY and JWT_SECRET_KEY!
    ) else (
        echo        .env.example not found -- skipping .env creation.
    )
)

REM ----------------------------------------------------------------
REM 5. Initialize the SQLite database
REM ----------------------------------------------------------------
echo.
echo [5/5] Initializing SQLite database ...
venv\Scripts\python -c "from app import create_app, db; app = create_app(); ctx = app.app_context(); ctx.push(); db.create_all(); print('Database initialized.')"
if errorlevel 1 (
    echo ERROR: Database initialization failed.
    echo        Make sure all app\ source files are present.
    pause
    exit /b 1
)

REM ----------------------------------------------------------------
REM Done
REM ----------------------------------------------------------------
echo.
echo ============================================================
echo   Setup complete!
echo ============================================================
echo.
echo   Start the server:  venv\Scripts\python run.py
echo   Then open:         https://localhost:5000
echo.
pause

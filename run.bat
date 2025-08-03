@echo off
echo Setting up and running Python project...

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo Failed to create virtual environment. Make sure Python is installed.
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Check if requirements are installed by trying to import cryptography
python -c "import cryptography" 2>nul
if errorlevel 1 (
    echo Installing requirements...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo Failed to install requirements.
        pause
        exit /b 1
    )
) else (
    echo Requirements already installed.
)

REM Run the main script
echo Running main.py...
python main.py

REM Keep window open to see output
pause
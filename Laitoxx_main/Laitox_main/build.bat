@echo off
REM Build script for Windows

echo ========================================
echo Laitoxx Native Modules Build (Windows)
echo ========================================
echo.

python build.py %*

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build completed successfully!
) else (
    echo.
    echo Build failed with error code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

pause

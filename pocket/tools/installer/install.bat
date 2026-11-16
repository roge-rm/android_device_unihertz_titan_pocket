@echo off
rem Starts the Titan Pocket installer. Needs Python 3.9 or later and Google's platform-tools
rem (adb.exe and fastboot.exe), looked for next to this file, on PATH and in the usual SDK folders.
setlocal
cd /d "%~dp0"

set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul && set "PY=py -3"
if not defined PY python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul && set "PY=python"
if not defined PY (
    echo Python 3.9 or later is missing.
    echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH", then run this again.
    goto end
)

set "ADB="
set "FASTBOOT="
for %%D in ("%~dp0platform-tools" "%USERPROFILE%\platform-tools" "%LOCALAPPDATA%\Android\Sdk\platform-tools") do (
    if not defined ADB if exist "%%~D\adb.exe" set "ADB=%%~D\adb.exe"
    if not defined FASTBOOT if exist "%%~D\fastboot.exe" set "FASTBOOT=%%~D\fastboot.exe"
)
if not defined ADB for /f "delims=" %%P in ('where adb.exe 2^>nul') do if not defined ADB set "ADB=%%P"
if not defined FASTBOOT for /f "delims=" %%P in ('where fastboot.exe 2^>nul') do if not defined FASTBOOT set "FASTBOOT=%%P"
if not defined ADB echo adb.exe is missing.
if not defined FASTBOOT echo fastboot.exe is missing.
if not defined ADB goto tools
if not defined FASTBOOT goto tools

%PY% tools\pocket-install.py --adb "%ADB%" --fastboot "%FASTBOOT%" %*
goto end

:tools
echo Download Google's platform-tools from
echo   https://developer.android.com/tools/releases/platform-tools
echo and unzip it here, so there is a platform-tools folder next to install.bat, then run this again.

:end
echo.
pause
endlocal

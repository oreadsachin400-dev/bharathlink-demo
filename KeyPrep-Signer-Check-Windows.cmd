@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem BharathLink KeyPrep ONLY TEST v40 — READ-ONLY installed signer check.
rem NO APK build, install, uninstall, reset, root, OTP or private-key access.
rem Run locally only on a trusted Windows PC with your original phone attached.
cd /d "%~dp0"
if errorlevel 1 goto BLOCKED
if not exist "scripts\audit_installed_keyprep_signer.py" (
  echo BLOCKED: Open this launcher from the full reviewed BharathLink repository folder.
  goto BLOCKED
)
if not exist "scripts\check_keyprep_signing.py" (
  echo BLOCKED: The archived signing comparison script is missing.
  goto BLOCKED
)
set "SDK=%LOCALAPPDATA%\Android\Sdk"
if defined ANDROID_SDK_ROOT if exist "%ANDROID_SDK_ROOT%\platform-tools\adb.exe" set "SDK=%ANDROID_SDK_ROOT%"
if defined ANDROID_HOME if exist "%ANDROID_HOME%\platform-tools\adb.exe" set "SDK=%ANDROID_HOME%"
if not exist "%SDK%\platform-tools\adb.exe" (
  echo BLOCKED: Official Android SDK Platform Tools not found.
  echo Open Android Studio - SDK Manager - SDK Tools, and check Android SDK Platform-Tools.
  echo This launcher will NOT install or download any software.
  goto BLOCKED
)
set "BT="
for /d %%D in ("%SDK%\build-tools\*") do if exist "%%~fD\apksigner.bat" if exist "%%~fD\aapt.exe" set "BT=%%~fD"
if not defined BT (
  echo BLOCKED: Android SDK Build-Tools with apksigner and aapt not found.
  echo Open Android Studio - SDK Manager - SDK Tools, and check Android SDK Build-Tools.
  goto BLOCKED
)
set "PATH=%SDK%\platform-tools;%BT%;%PATH%"
set "PYEXE="
where py >nul 2>nul
if not errorlevel 1 (
  py -3 --version >nul 2>nul
  if not errorlevel 1 set "PYEXE=py"
)
if not defined PYEXE (
  where python >nul 2>nul
  if not errorlevel 1 set "PYEXE=python"
)
if not defined PYEXE (
  echo BLOCKED: Python 3 not found. Install a trusted Python 3 and reopen this folder.
  echo No Python will be downloaded automatically.
  goto BLOCKED
)
echo.
echo BharathLink KeyPrep signer check - READ ONLY
echo No APK installation or update. No phone identity or private keys uploaded.
echo Please keep the original KeyPrep installed on the phone.
echo.
if /i "%PYEXE%"=="py" (
  py -3 "scripts\audit_installed_keyprep_signer.py"
) else (
  python "scripts\audit_installed_keyprep_signer.py"
)
if errorlevel 1 goto BLOCKED
echo.
echo The archived public signing certificate MATCHED the installed KeyPrep v40.
echo This does NOT confirm the private signing key or Play Protect clearance.
if not defined CI pause
exit /b 0

:BLOCKED
echo.
echo No phone data or APK was modified. Keep KeyPrep installed.
echo Do NOT disable Play Protect or attempt a force-install.
if not defined CI pause
exit /b 1

@echo off
setlocal enabledelayedexpansion
title AetherScope V2.4 - Control Center
chcp 65001 >nul

set "SCRIPT_DIR=%~dp0"
set "REPO_DIR=C:\Users\1234\Desktop\Projets\aether-engine\"
set "ENGINE_EXE="
set "MCP_EXE="
set "MC_RUNNER_EXE="

if exist "%SCRIPT_DIR%target\release\aether-engine.exe" set "ENGINE_EXE=%SCRIPT_DIR%target\release\aether-engine.exe"
if not defined ENGINE_EXE if exist "%REPO_DIR%target\release\aether-engine.exe" set "ENGINE_EXE=%REPO_DIR%target\release\aether-engine.exe"
if not defined ENGINE_EXE if exist "%SCRIPT_DIR%aether-engine.exe" set "ENGINE_EXE=%SCRIPT_DIR%aether-engine.exe"
if not defined ENGINE_EXE if exist "%REPO_DIR%aether-engine.exe" set "ENGINE_EXE=%REPO_DIR%aether-engine.exe"
if not defined ENGINE_EXE if exist "%LOCALAPPDATA%\AetherScope\bin\aether-engine.exe" set "ENGINE_EXE=%LOCALAPPDATA%\AetherScope\bin\aether-engine.exe"

if exist "%SCRIPT_DIR%target\release\aetherscope-mcp.exe" set "MCP_EXE=%SCRIPT_DIR%target\release\aetherscope-mcp.exe"
if not defined MCP_EXE if exist "%REPO_DIR%target\release\aetherscope-mcp.exe" set "MCP_EXE=%REPO_DIR%target\release\aetherscope-mcp.exe"
if not defined MCP_EXE if exist "%SCRIPT_DIR%aetherscope-mcp.exe" set "MCP_EXE=%SCRIPT_DIR%aetherscope-mcp.exe"
if not defined MCP_EXE if exist "%LOCALAPPDATA%\AetherScope\bin\aetherscope-mcp.exe" set "MCP_EXE=%LOCALAPPDATA%\AetherScope\bin\aetherscope-mcp.exe"

if exist "%SCRIPT_DIR%target\release\aether-mc-runner.exe" set "MC_RUNNER_EXE=%SCRIPT_DIR%target\release\aether-mc-runner.exe"
if not defined MC_RUNNER_EXE if exist "%SCRIPT_DIR%aether-mc-runner.exe" set "MC_RUNNER_EXE=%SCRIPT_DIR%aether-mc-runner.exe"
if not defined MC_RUNNER_EXE if exist "%LOCALAPPDATA%\AetherScope\bin\aether-mc-runner.exe" set "MC_RUNNER_EXE=%LOCALAPPDATA%\AetherScope\bin\aether-mc-runner.exe"

if not defined ENGINE_EXE (
    echo [ERREUR] Impossible de trouver aether-engine.exe !
    echo Veuillez compiler le projet via cargo build --release ou executer install.ps1.
    pause
    exit /b 1
)

:MENU
cls
echo ==============================================================
echo       🪐 AETHERSCOPE V2.4 — COCKPIT SPATIAL ET MCP SUITE
echo ==============================================================
echo   Binaire actif : %ENGINE_EXE%
echo.
echo   [1] 🚀 Lancer le Cockpit Spatial (Svelte 5 + WebGL 2 + Axum 3030)
echo   [2] 🤖 Tester le Serveur MCP Stdio interactif (aetherscope-mcp.exe)
echo   [3] 🌐 Lancer le Serveur en Arriere-Plan (Mode Headless Axum 3030)
echo   [4] 🔌 Configurer les Clients IA (Claude / Antigravity / Cursor)
echo   [5] 🎯 Scanner et Synchroniser un Projet (SAST Live Synchro GUI)
echo   [6] ⛏️ Lancer Aether Minecraft Cockpit (Web Flask + Runner)
echo   [7] 🧹 Liberer le port 3030 (Fermer tous les processus Aether)
echo   [8] 📦 Installer / Mettre a jour AetherScope dans Windows (PATH + Bureau)
echo   [9] ❌ Quitter
echo.
echo ==============================================================
set /p "CHOICE=Choisissez une option (1-9) [defaut: 1] : "

if "%CHOICE%"=="" set "CHOICE=1"
if "%CHOICE%"=="1" goto LAUNCH_GUI
if "%CHOICE%"=="2" goto LAUNCH_MCP
if "%CHOICE%"=="3" goto LAUNCH_HEADLESS
if "%CHOICE%"=="4" goto CONFIG_MCP
if "%CHOICE%"=="5" goto SCAN_SAST
if "%CHOICE%"=="6" goto LAUNCH_MC
if "%CHOICE%"=="7" goto KILL_PORT
if "%CHOICE%"=="8" goto RUN_INSTALL
if "%CHOICE%"=="9" goto QUIT

echo Option invalide.
timeout /t 2 >nul
goto MENU

:SYNC_BINARIES
taskkill /F /IM aether-engine.exe >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :3030 ^| findstr LISTENING') do (
    set "PORT_PID=%%a"
    if defined PORT_PID (
        taskkill /PID !PORT_PID! /F >nul 2>&1
    )
)
if exist "%LOCALAPPDATA%\AetherScope\bin" (
    copy /Y "%ENGINE_EXE%" "%LOCALAPPDATA%\AetherScope\bin\aether-engine.exe" >nul 2>&1
    if defined MCP_EXE copy /Y "%MCP_EXE%" "%LOCALAPPDATA%\AetherScope\bin\aetherscope-mcp.exe" >nul 2>&1
)
if exist "%SCRIPT_DIR%Cargo.toml" (
    if /I not "%ENGINE_EXE%"=="%SCRIPT_DIR%aether-engine.exe" (
        copy /Y "%ENGINE_EXE%" "%SCRIPT_DIR%aether-engine.exe" >nul 2>&1
    )
)
exit /b 0

:LAUNCH_GUI
cls
echo [INFO] Verification du port 3030 et synchronisation des binaires V2.4...
call :SYNC_BINARIES
echo [INFO] Demarrage du Cockpit AetherScope V2.4...
start "" "%ENGINE_EXE%"

echo [OK] Cockpit V2.4 actif sur http://127.0.0.1:3030 !
echo Vos assistants IA (Claude, Cursor, Antigravity) communiquent directement via le serveur MCP standard stdio.
timeout /t 2 >nul
exit /b 0

:LAUNCH_MCP
cls
echo ==============================================================
echo       🤖 AETHERSCOPE V2.4 — SERVEUR MCP STDIO DEDIE
echo ==============================================================
echo.
echo Le serveur MCP communique en JSON-RPC 2.0 sur stdio.
echo Port de synchronisation HTTP Cockpit : 3030
echo.
if not defined MCP_EXE (
    echo [ERREUR] Impossible de trouver aetherscope-mcp.exe !
    pause
    goto MENU
)
echo Demarrage du serveur MCP (Ctrl+C pour arreter)...
"%MCP_EXE%" --port 3030
pause
goto MENU

:LAUNCH_HEADLESS
cls
echo [INFO] Synchronisation et lancement du serveur Axum + FileWatcher sans GUI...
call :SYNC_BINARIES
echo Le serveur restera actif sur http://127.0.0.1:3030
"%ENGINE_EXE%" --no-gui
pause
goto MENU

:CONFIG_MCP
cls
echo [INFO] Execution du configurateur MCP...
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%setup-mcp.ps1"
echo.
pause
goto MENU

:SCAN_SAST
cls
set /p "SCAN_PATH=Chemin du projet a scanner [defaut: .] : "
if "%SCAN_PATH%"=="" set "SCAN_PATH=."
echo [INFO] Audit SAST et Synchronisation en direct en cours sur %SCAN_PATH%...
"%ENGINE_EXE%" --path "%SCAN_PATH%" --audit-only
echo.
echo [OK] Rapport disponible dans : %SCAN_PATH%\.aether\LIVE_AUDIT.md
pause
goto MENU

:LAUNCH_MC
cls
echo [INFO] Lancement du Control-Plane Minecraft Cockpit (http://127.0.0.1:5000)...
start http://127.0.0.1:5000
python "%SCRIPT_DIR%apps\aethercraft\control-plane\app.py"
pause
goto MENU

:KILL_PORT
cls
echo [INFO] Arret des processus aether-engine et aetherscope-mcp...
taskkill /F /IM aether-engine.exe >nul 2>&1
taskkill /F /IM aetherscope-mcp.exe >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :3030 ^| findstr LISTENING') do (
    set "PORT_PID=%%a"
    if defined PORT_PID (
        taskkill /PID !PORT_PID! /F >nul 2>&1
    )
)
echo [OK] Tous les processus AetherScope ont ete arretes et le port 3030 est libere !
timeout /t 2 >nul
goto MENU

:RUN_INSTALL
cls
echo [INFO] Lancement de l'installateur Windows...
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install.ps1"
echo.
pause
goto MENU

:QUIT
exit /b 0

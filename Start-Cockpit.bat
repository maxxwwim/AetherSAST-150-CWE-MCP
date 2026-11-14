@echo off
setlocal enabledelayedexpansion
title AetherScope V2.4 - Lancement du Cockpit
chcp 65001 >nul

set "SCRIPT_DIR=%~dp0"
set "REPO_DIR=C:\Users\1234\Desktop\Projets\aether-engine\"
set "ENGINE_EXE="
set "MCP_EXE="

:: 1. Priorite absolue au binaire fraichement compile dans target\release
if exist "%SCRIPT_DIR%target\release\aether-engine.exe" set "ENGINE_EXE=%SCRIPT_DIR%target\release\aether-engine.exe"
if not defined ENGINE_EXE if exist "%REPO_DIR%target\release\aether-engine.exe" set "ENGINE_EXE=%REPO_DIR%target\release\aether-engine.exe"
if not defined ENGINE_EXE if exist "%SCRIPT_DIR%aether-engine.exe" set "ENGINE_EXE=%SCRIPT_DIR%aether-engine.exe"
if not defined ENGINE_EXE if exist "%REPO_DIR%aether-engine.exe" set "ENGINE_EXE=%REPO_DIR%aether-engine.exe"
if not defined ENGINE_EXE if exist "%LOCALAPPDATA%\AetherScope\bin\aether-engine.exe" set "ENGINE_EXE=%LOCALAPPDATA%\AetherScope\bin\aether-engine.exe"

if exist "%SCRIPT_DIR%target\release\aetherscope-mcp.exe" set "MCP_EXE=%SCRIPT_DIR%target\release\aetherscope-mcp.exe"
if not defined MCP_EXE if exist "%REPO_DIR%target\release\aetherscope-mcp.exe" set "MCP_EXE=%REPO_DIR%target\release\aetherscope-mcp.exe"
if not defined MCP_EXE if exist "%SCRIPT_DIR%aetherscope-mcp.exe" set "MCP_EXE=%SCRIPT_DIR%aetherscope-mcp.exe"
if not defined MCP_EXE if exist "%LOCALAPPDATA%\AetherScope\bin\aetherscope-mcp.exe" set "MCP_EXE=%LOCALAPPDATA%\AetherScope\bin\aetherscope-mcp.exe"

if not defined ENGINE_EXE (
    echo [ERREUR] aether-engine.exe est introuvable.
    pause
    exit /b 1
)

:: 2. Arret propre de toute ancienne instance (y compris celle lancee par MCP dans AppData\Local\AetherScope\bin)
echo [INFO] Nettoyage des anciennes instances sur le port 3030...
taskkill /F /IM aether-engine.exe >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :3030 ^| findstr LISTENING') do (
    set "PORT_PID=%%a"
    if defined PORT_PID (
        taskkill /PID !PORT_PID! /F >nul 2>&1
    )
)

:: 3. Synchronisation automatique du binaire recent vers AppData\Local\AetherScope\bin et la racine
if exist "%LOCALAPPDATA%\AetherScope\bin" (
    copy /Y "%ENGINE_EXE%" "%LOCALAPPDATA%\AetherScope\bin\aether-engine.exe" >nul 2>&1
    if defined MCP_EXE copy /Y "%MCP_EXE%" "%LOCALAPPDATA%\AetherScope\bin\aetherscope-mcp.exe" >nul 2>&1
)
if exist "%SCRIPT_DIR%Cargo.toml" (
    if /I not "%ENGINE_EXE%"=="%SCRIPT_DIR%aether-engine.exe" (
        copy /Y "%ENGINE_EXE%" "%SCRIPT_DIR%aether-engine.exe" >nul 2>&1
    )
)

:: 4. Demarrage immediat du Cockpit WebGL 2 & Svelte 5 v2.4 sur 127.0.0.1:3030
echo [INFO] Lancement du Cockpit AetherScope V2.4 (%ENGINE_EXE%) sur http://127.0.0.1:3030...
start "" "%ENGINE_EXE%"

echo [OK] Cockpit V2.4 actif ! Vos assistants IA (Claude, Cursor, Antigravity) sont synchronises.
timeout /t 2 >nul
exit /b 0

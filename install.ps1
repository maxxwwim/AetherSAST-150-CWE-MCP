# ==========================================================
# AetherScope V2.4 - Windows Installer (PowerShell)
# ==========================================================
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "AetherScope"),
    [switch]$SkipMcp,
    [switch]$SkipShortcut
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " INSTALLATEUR AETHERSCOPE V2.4 (WINDOWS X64) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$binDir = Join-Path $InstallDir "bin"

# 1. Recherche des executables (priorite a target\release pour toujours prendre le dernier build)
$engineExe = $null
$mcpExe = $null
$mcRunnerExe = $null
$pluginToolExe = $null

$candidates = @(
    (Join-Path $scriptDir "target\release"),
    $scriptDir
)

foreach ($c in $candidates) {
    $e = Join-Path $c "aether-engine.exe"
    $m = Join-Path $c "aetherscope-mcp.exe"
    $r = Join-Path $c "aether-mc-runner.exe"
    $p = Join-Path $c "aether-plugin-tool.exe"
    if (-not $engineExe -and (Test-Path $e)) { $engineExe = (Resolve-Path $e).Path }
    if (-not $mcpExe -and (Test-Path $m)) { $mcpExe = (Resolve-Path $m).Path }
    if (-not $mcRunnerExe -and (Test-Path $r)) { $mcRunnerExe = (Resolve-Path $r).Path }
    if (-not $pluginToolExe -and (Test-Path $p)) { $pluginToolExe = (Resolve-Path $p).Path }
}

if (-not $engineExe) {
    Write-Host "[ERREUR] aether-engine.exe est introuvable." -ForegroundColor Red
    Write-Host "Veuillez compiler le projet via: cargo build --release" -ForegroundColor Yellow
    exit 1
}

Write-Host "[INFO] Dossier cible : $InstallDir" -ForegroundColor White
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
}

# 2. Arret de l'ancienne instance aether-engine en cours d'execution avant copie
Get-Process aether-engine -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 250

# 3. Copie des fichiers
Write-Host "[INFO] Copie des binaires V2.4 vers $binDir..." -ForegroundColor DarkGray
Copy-Item -Path $engineExe -Destination (Join-Path $binDir "aether-engine.exe") -Force
if ($mcpExe) {
    try {
        Copy-Item -Path $mcpExe -Destination (Join-Path $binDir "aetherscope-mcp.exe") -Force
    } catch {
        Write-Host "  [i] aetherscope-mcp.exe est en cours d'utilisation par l'IDE (sera mis a jour au prochain lancement)." -ForegroundColor DarkGray
    }
}
if ($mcRunnerExe) {
    Copy-Item -Path $mcRunnerExe -Destination (Join-Path $binDir "aether-mc-runner.exe") -Force
}
if ($pluginToolExe) {
    Copy-Item -Path $pluginToolExe -Destination (Join-Path $binDir "aether-plugin-tool.exe") -Force
}

$launcherSrc = Join-Path $scriptDir "AetherScope-Launcher.bat"
if (Test-Path $launcherSrc) {
    Copy-Item -Path $launcherSrc -Destination (Join-Path $InstallDir "AetherScope-Launcher.bat") -Force
}
$startCockpitSrc = Join-Path $scriptDir "Start-Cockpit.bat"
if (Test-Path $startCockpitSrc) {
    Copy-Item -Path $startCockpitSrc -Destination (Join-Path $InstallDir "Start-Cockpit.bat") -Force
}
$setupMcpSrc = Join-Path $scriptDir "setup-mcp.ps1"
if (Test-Path $setupMcpSrc) {
    Copy-Item -Path $setupMcpSrc -Destination (Join-Path $InstallDir "setup-mcp.ps1") -Force
}

# 4. Ajout au PATH Utilisateur Windows
Write-Host "[INFO] Configuration de la variable PATH..." -ForegroundColor White
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$paths = $userPath -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
if ($paths -notcontains $binDir) {
    $newUserPath = ($paths + $binDir) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    $env:Path = "$env:Path;$binDir"
    Write-Host "  [OK] $binDir ajoute au PATH utilisateur !" -ForegroundColor Green
} else {
    Write-Host "  [OK] Le dossier est deja present dans le PATH." -ForegroundColor DarkGray
}

# 5. Creation du raccourci Bureau
if (-not $SkipShortcut) {
    try {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $shortcutPath = Join-Path $desktopPath "AetherScope V2.lnk"
        $targetExe = Join-Path $binDir "aether-engine.exe"
        $launcherTarget = Join-Path $InstallDir "Start-Cockpit.bat"
        if (Test-Path $launcherTarget) {
            $targetExe = $launcherTarget
        }

        $wscript = New-Object -ComObject WScript.Shell
        $shortcut = $wscript.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $targetExe
        $shortcut.WorkingDirectory = $scriptDir
        $shortcut.Description = "AetherScope V2.4 - Cockpit Spatial 3D Svelte 5 et Linter SAST"
        $shortcut.Save()
        Write-Host "  [OK] Raccourci mis a jour sur le Bureau : $shortcutPath" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] Echec creation raccourci Bureau : $_" -ForegroundColor Yellow
    }
}

# 6. Configuration automatique du MCP
if (-not $SkipMcp) {
    Write-Host ""
    $mcpScript = Join-Path $InstallDir "setup-mcp.ps1"
    if (Test-Path $mcpScript) {
        & $mcpScript
    } elseif (Test-Path $setupMcpSrc) {
        & $setupMcpSrc
    }
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AETHERSCOPE V2.4 EST INSTALLE ET SYNCHRONISE !" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

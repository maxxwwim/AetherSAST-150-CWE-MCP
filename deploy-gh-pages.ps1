# Script de déploiement direct GitHub Pages (100% gratuit, sans utiliser de minutes GitHub Actions)
param()

$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot

Write-Host "📦 Construction du cockpit WebGL standalone..." -ForegroundColor Cyan
Push-Location "$rootDir\crates\desktop-shell\ui"
npm run build
Pop-Location

Write-Host "📦 Génération de docs/index.html avec le graphe AST embarqué..." -ForegroundColor Cyan
cargo test -p desktop-shell --bin aether_engine viewer::tests::test_export_docs_index_html

Write-Host "🚀 Déploiement sur la branche gh-pages..." -ForegroundColor Cyan
$tempRepo = Join-Path ([System.IO.Path]::GetTempPath()) "aether-gh-pages"
if (Test-Path $tempRepo) { Remove-Item -Recurse -Force $tempRepo }
New-Item -ItemType Directory -Path $tempRepo | Out-Null

Copy-Item -Recurse "$rootDir\crates\desktop-shell\dist\*" $tempRepo
Copy-Item "$rootDir\docs\index.html" "$tempRepo\index.html"
Set-Content (Join-Path $tempRepo ".nojekyll") ""

Push-Location $tempRepo
git init
git config user.name "Antigravity"
git config user.email "antigravity@google.com"
git checkout -b gh-pages
git add .
git commit -m "Deploy AetherScope WebGL standalone demo to GitHub Pages"
git remote add origin https://github.com/maxxwwim/AetherSAST-150-CWE-MCP.git
git push origin gh-pages --force
Pop-Location

Remove-Item -Recurse -Force $tempRepo
Write-Host "✅ Démo déployée avec succès sur https://maxxwwim.github.io/AetherSAST-150-CWE-MCP/ !" -ForegroundColor Green

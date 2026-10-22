# RAG Attack Lab: two-minute demo.
#
# Runs the whole story from a clean store: ingest, attack the vulnerable lab (4 of 4 succeed),
# turn on SECURE_MODE, attack again (0 of 4 succeed). Everything stays on this machine.
#
# Run from the repo root, with the virtual environment set up and Ollama running:
#     .\docs\demo\demo.ps1            # pauses between steps, for narrating while recording
#     .\docs\demo\demo.ps1 -NoPause   # runs straight through
#
# Output goes to demo_output\ (git-ignored), so the committed evidence in findings\ is never touched.

param(
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"

$RagLab = Join-Path $PSScriptRoot "..\..\.venv\Scripts\rag-lab.exe"
$OutDir = "demo_output"

if (-not (Test-Path $RagLab)) {
    Write-Host "Not found: $RagLab. Set up the virtual environment first (see README.md, Setup)." -ForegroundColor Red
    exit 1
}

function Show-Step([string]$Title, [string]$Command) {
    Write-Host ""
    Write-Host "== $Title" -ForegroundColor Cyan
    Write-Host "> $Command" -ForegroundColor DarkGray
}

function Wait-Step {
    if (-not $NoPause) {
        Read-Host "Press Enter to continue" | Out-Null
    }
}

# Start from the vulnerable default, whatever .env says, and remember the old value to restore it.
$OriginalSecureMode = $env:SECURE_MODE
$env:SECURE_MODE = "false"

try {
    Show-Step "1. Check the setup" "rag-lab doctor"
    & $RagLab doctor
    if ($LASTEXITCODE -ne 0) { throw "rag-lab doctor failed. Is Ollama running with llama3.1:8b and nomic-embed-text?" }
    Wait-Step

    Show-Step "2. Start from a clean store and ingest the fictional company documents" "rag-lab reset; rag-lab ingest"
    & $RagLab reset
    & $RagLab ingest
    Wait-Step

    Show-Step "3. Attack the vulnerable lab (SECURE_MODE off)" "rag-lab attack --out $OutDir"
    & $RagLab attack --out $OutDir
    Wait-Step

    Show-Step "4. Turn on the fixes" '$env:SECURE_MODE = "true"'
    $env:SECURE_MODE = "true"
    Write-Host "SECURE_MODE=$env:SECURE_MODE"
    Wait-Step

    Show-Step "5. Run the same attacks again (SECURE_MODE on)" "rag-lab attack --out $OutDir"
    & $RagLab attack --out $OutDir
    Write-Host ""
    Write-Host "Before: $OutDir\findings.md    After: $OutDir\retest.md" -ForegroundColor Cyan
}
finally {
    # Leave the shell the way it was.
    if ($null -eq $OriginalSecureMode) { Remove-Item Env:SECURE_MODE -ErrorAction SilentlyContinue }
    else { $env:SECURE_MODE = $OriginalSecureMode }
}

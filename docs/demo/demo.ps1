# RAG Attack Lab: two-minute demo.
#
# Runs the whole story from a clean store: reset, ingest, check the setup, attack the vulnerable
# lab (4 of 4 succeed), turn on SECURE_MODE, attack again (0 of 4 succeed). Everything stays on
# this machine.
#
# Needs the virtual environment set up and Ollama running with llama3.1:8b and nomic-embed-text.
# Run it directly (do not pipe or redirect its output):
#     .\docs\demo\demo.ps1            # pauses between steps, for narrating while recording
#     .\docs\demo\demo.ps1 -NoPause   # runs straight through
#
# It works from any folder: it switches to the repo root first, because DATA_DIR, CHROMA_DIR, and
# the output folder are relative to it. Output goes to demo_output\ (git-ignored), so the committed
# evidence in findings\ is never touched.

param(
    [switch]$NoPause
)

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$RagLab = Join-Path $RepoRoot ".venv\Scripts\rag-lab.exe"
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

# Run rag-lab and stop the demo if it fails, so a broken step never shows a misleading result.
function Invoke-RagLab {
    & $RagLab @args
    if ($LASTEXITCODE -ne 0) {
        throw "rag-lab $($args -join ' ') failed (exit code $LASTEXITCODE)."
    }
}

# Start from the vulnerable default, whatever .env says, and remember the old value to restore it.
$OriginalSecureMode = $env:SECURE_MODE
$env:SECURE_MODE = "false"
Push-Location $RepoRoot

try {
    Show-Step "1. Start from a clean store and ingest the fictional company documents" "rag-lab reset; rag-lab ingest"
    Invoke-RagLab reset
    Invoke-RagLab ingest
    Wait-Step

    Show-Step "2. Check the setup: local model, local embeddings, local store" "rag-lab doctor"
    Invoke-RagLab doctor
    Wait-Step

    Show-Step "3. Attack the vulnerable lab (SECURE_MODE off)" "rag-lab attack --out $OutDir"
    Invoke-RagLab attack --out $OutDir
    Wait-Step

    Show-Step "4. Turn on the fixes" '$env:SECURE_MODE = "true"'
    $env:SECURE_MODE = "true"
    Write-Host "SECURE_MODE=$env:SECURE_MODE"
    Wait-Step

    Show-Step "5. Run the same attacks again (SECURE_MODE on)" "rag-lab attack --out $OutDir"
    Invoke-RagLab attack --out $OutDir
    Write-Host ""
    Write-Host "Before: $OutDir\findings.md    After: $OutDir\retest.md" -ForegroundColor Cyan
}
catch {
    Write-Host $_ -ForegroundColor Red
    Write-Host "Is Ollama running with llama3.1:8b and nomic-embed-text? Try: rag-lab doctor" -ForegroundColor Red
    exit 1
}
finally {
    # Leave the shell the way it was.
    Pop-Location
    if ($null -eq $OriginalSecureMode) { Remove-Item Env:SECURE_MODE -ErrorAction SilentlyContinue }
    else { $env:SECURE_MODE = $OriginalSecureMode }
}

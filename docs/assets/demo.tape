# Records docs/assets/demo.gif from a live run against a local Ollama serving llama3.1:8b and nomic-embed-text.
# Run from the repository root with the virtual environment in .venv:
#   vhs docs/assets/demo.tape
# The layers script rewrites findings/llm01-layers.json, so record in a throwaway clone.

Output docs/assets/demo.gif

Set Shell "powershell"
Set FontSize 14
Set Width 900
Set Height 660
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 15ms
Set Framerate 12
Set WaitTimeout 180s

# Put the venv on PATH and use a plain prompt, so no local path shows on screen.
Hide
Type `Remove-Module PSReadLine -ErrorAction SilentlyContinue; $env:PATH = (Resolve-Path .venv\Scripts).Path + ';' + $env:PATH; $env:SECURE_MODE = 'false'; function prompt { '$ ' }; cls`
Enter
Sleep 2s
Show

Type "# Ingest fictional documents. One vendor newsletter hides an instruction."
Enter
Sleep 600ms
Type "rag-lab reset; rag-lab ingest"
Sleep 400ms
Enter
Wait+Screen /flagged suspicious/
Sleep 3s

Type "# Ask an ordinary question. SECURE_MODE is off."
Enter
Sleep 600ms
Type `rag-lab ask "What packaging and shipping updates are in the latest Brightway Supplies newsletter?"`
Sleep 400ms
Enter
Wait+Screen /Retrieved sources/
Sleep 7s

Type "cls"
Enter
Sleep 300ms
Type "# Test each layer with the quarantine bypassed: four questions, one run."
Enter
Sleep 600ms
Type "python scripts\llm01_layers.py"
Sleep 400ms
Enter
Wait+Screen /Wrote findings/
Sleep 5s

Type "# The same question with the fixes on: the newsletter is quarantined."
Enter
Sleep 600ms
Type `$env:SECURE_MODE = "true"`
Enter
Sleep 300ms
Type `rag-lab ask "What packaging and shipping updates are in the latest Brightway Supplies newsletter?"`
Sleep 400ms
Enter
Wait+Screen /Retrieved sources/
Sleep 8s

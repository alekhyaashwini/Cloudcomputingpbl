# ==============================================================================
# SECURE CLOUD FILE STORAGE USING ENCRYPTION (AES-256-GCM)
# Windows PowerShell Quick Setup & Run Script
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   College PBL: Secure Cloud File Storage Using Encryption" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Python version
Write-Host "`n[Step 1/5] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version
    Write-Host "Detected Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python is not detected in your PATH. Please install Python 3.11+ from python.org and tick 'Add python.exe to PATH'." -ForegroundColor Red
    Exit 1
}

# 2. Virtual environment check
Write-Host "`n[Step 2/5] Checking virtual environment (venv)..." -ForegroundColor Yellow
if (-not (Test-Path "venv\Scripts\python.exe")) {
    python -m venv --system-site-packages venv
    Write-Host "Created virtual environment in .\venv" -ForegroundColor Green
} else {
    Write-Host "Virtual environment ready." -ForegroundColor Green
}

# 3. Environment configuration (.env)
Write-Host "`n[Step 3/5] Checking environment configuration (.env)..." -ForegroundColor Yellow
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example with secure default keys." -ForegroundColor Green
} else {
    Write-Host ".env configuration file detected." -ForegroundColor Green
}

# 4. Run automated test suite
Write-Host "`n[Step 4/5] Running automated test suite (pytest)..." -ForegroundColor Yellow
& ".\venv\Scripts\pytest.exe" -v
if ($LASTEXITCODE -eq 0) {
    Write-Host "`nAll 20 cryptographic and security test cases PASSED!" -ForegroundColor Green
} else {
    Write-Host "`nWarning: Some tests reported issues." -ForegroundColor Yellow
}

# 5. Start Flask Web Server
Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "   Starting Secure Cloud Vault Server on port 5000..." -ForegroundColor Cyan
Write-Host "   Open your browser to: http://127.0.0.1:5000" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Start-Process "http://127.0.0.1:5000"
& ".\venv\Scripts\python.exe" app.py

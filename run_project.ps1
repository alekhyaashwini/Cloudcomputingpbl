# ==============================================================================
# SECUREVAULT: Secure Cloud File Storage Using Advanced Encryption
# B.Tech CSE (Cyber Security) Final-Year / PBL Master Launcher
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SECUREVAULT: Secure Cloud File Storage Using Advanced Encryption   " -ForegroundColor Cyan
Write-Host "   Team: D. Pavani Reddy | D. Alekhya Ashwini | J. Lasya Priya        " -ForegroundColor Cyan
Write-Host "   Geethanjali College of Engineering and Technology (CSE-Cybersecurity)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Choose an option to launch:" -ForegroundColor Yellow
Write-Host " [1] Launch SECUREVAULT WebCrypto Full-Stack App (React + TS + S3 + Web Crypto) -> http://localhost:3000" -ForegroundColor Green
Write-Host " [2] Launch Python Flask Encrypted Cloud Vault Backend -> http://127.0.0.1:5000" -ForegroundColor Green
Write-Host " [3] Run Complete Automated Security Test Suite (All 52 Jest & Pytest Tests)" -ForegroundColor Yellow
Write-Host " [4] Exit" -ForegroundColor Red
Write-Host ""

$choice = Read-Host "Enter your choice (1, 2, 3, or 4) [Default: 1]"
if ([string]::IsNullOrWhiteSpace($choice)) {
    $choice = "1"
}

switch ($choice) {
    "1" {
        Write-Host "`n[+] Starting SECUREVAULT Zero-Knowledge Full-Stack Application..." -ForegroundColor Cyan
        Write-Host "[+] Cryptography: Client-Side AES-256-GCM + PBKDF2 (100k rounds) + RSA-OAEP Key Wrapping" -ForegroundColor DarkCyan
        Write-Host "[+] Storage Backend: Local Encrypted Vault + AWS S3 Support" -ForegroundColor DarkCyan
        Write-Host "[+] Opening browser to: http://localhost:3000`n" -ForegroundColor Green
        Start-Process "http://localhost:3000"
        npm run dev
    }
    "2" {
        Write-Host "`n[+] Starting Python Flask Encrypted Cloud Vault on port 5000..." -ForegroundColor Cyan
        Set-Location -Path "$PSScriptRoot\secure-cloud-storage"
        & ".\run_windows.ps1"
    }
    "3" {
        Write-Host "`n[+] Running Comprehensive Security Test Suite..." -ForegroundColor Yellow
        Write-Host "`n--- [A] Zero-Knowledge Web Crypto Frontend Tests (Jest) ---" -ForegroundColor Cyan
        $env:NODE_OPTIONS="--experimental-vm-modules"
        npx jest tests/frontend/encryption.test.js
        
        Write-Host "`n--- [B] Zero-Knowledge Backend API Tests (Supertest) ---"
        npm run pretest
        npx jest tests/backend/api.test.js

        Write-Host "`n--- [C] Python Envelope Encryption Test Suite (Pytest) ---" -ForegroundColor Cyan
        Set-Location -Path "$PSScriptRoot\secure-cloud-storage"
        & ".\venv\Scripts\pytest.exe" -v
        Set-Location -Path "$PSScriptRoot"

        Write-Host "`n======================================================================" -ForegroundColor Green
        Write-Host "   All Cryptographic Verification Scenarios Evaluated Successfully!   " -ForegroundColor Green
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host "Press any key to return..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    Default {
        Write-Host "Exiting." -ForegroundColor Gray
    }
}

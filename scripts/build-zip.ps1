<#
.SYNOPSIS
    Packaging WordPress Plugin WP Root Guard ke file ZIP produksi.

.DESCRIPTION
    Skrip PowerShell untuk membuat arsip ZIP produksi WP Root Guard yang siap di-install di WordPress.
    Mengabaikan file development, tests, docs, docker, dan git.

.PARAMETER OutputDir
    Direktori tujuan penyimpanan file ZIP (default: ./dist).

.PARAMETER SkipLint
    Lewati pengecekan sintaks PHP sebelum packaging.

.EXAMPLE
    .\scripts\build-zip.ps1
    .\scripts\build-zip.ps1 -OutputDir "C:\Builds" -SkipLint
#>

[CmdletBinding()]
param (
    [string]$OutputDir = "",
    [switch]$SkipLint
)

$ErrorActionPreference = "Stop"

# Direktori proyek
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PluginRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path

# Konfigurasi Default
$PluginSlug = "wp-root-guard"
$MainPluginFile = Join-Path $PluginRoot "$PluginSlug.php"

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $PluginRoot "dist"
}

# Fungsi Helper Output
function Log-Info([string]$msg) {
    Write-Host "[*] " -ForegroundColor Cyan -NoNewline
    Write-Host $msg
}

function Log-Success([string]$msg) {
    Write-Host "[+] " -ForegroundColor Green -NoNewline
    Write-Host $msg
}

function Log-Warn([string]$msg) {
    Write-Host "[!] " -ForegroundColor Yellow -NoNewline
    Write-Host $msg
}

function Log-Error([string]$msg) {
    Write-Host "[x] " -ForegroundColor Red -NoNewline
    Write-Host $msg
}

# 1. Verifikasi File Utama
if (-not (Test-Path -Path $MainPluginFile -PathType Leaf)) {
    Log-Error "File utama plugin tidak ditemukan: $MainPluginFile"
    exit 1
}

# 2. Ekstrak Versi dari Main Plugin File
$Version = "latest"
$content = Get-Content -Path $MainPluginFile -Raw
if ($content -match '(?m)^\s*\*?\s*Version:\s*([0-9\.]+)') {
    $Version = $Matches[1].Trim()
} elseif ($content -match "define\(\s*'WP_ROOT_GUARD_VERSION'\s*,\s*'([0-9\.]+)'\s*\)") {
    $Version = $Matches[1].Trim()
} else {
    Log-Warn "Gagal mendeteksi versi secara otomatis. Menggunakan versi fallback 'latest'."
}

$ZipFilename = "$PluginSlug-v$Version.zip"
$LatestZipFilename = "$PluginSlug.zip"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   WP Root Guard — Production Packaging Tool (PS)   " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Log-Info "Plugin Slug : $PluginSlug"
Log-Info "Versi       : $Version"
Log-Info "Target Dir  : $OutputDir"
Log-Info "File Output : $ZipFilename"

# 3. Lakukan Linting PHP (Opsional)
$phpCmd = Get-Command "php" -ErrorAction SilentlyContinue
if (-not $SkipLint -and $phpCmd) {
    Log-Success "Memeriksa sintaks PHP (linting)..."
    $phpFiles = Get-ChildItem -Path $PluginRoot -Filter "*.php" -Recurse | Where-Object {
        $_.FullName -notmatch '[\\/](\.git|dist|node_modules|vendor)[\\/]'
    }

    foreach ($file in $phpFiles) {
        $output = & php -l $file.FullName 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host $output -ForegroundColor Red
            Log-Error "Linting gagal pada berkas: $($file.FullName)"
            exit 1
        }
    }
    Log-Success "Semua file PHP valid (0 sintaks error)."
}

# 4. Siapkan Direktori Staging Sementara
$TempBase = Join-Path ([System.IO.Path]::GetTempPath()) ("wprg_build_" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
$StageDir = Join-Path $TempBase $PluginSlug

try {
    New-Item -Path $StageDir -ItemType Directory -Force | Out-Null
    Log-Success "Menyiapkan berkas produksi ke staging directory..."

    # Salin berkas utama
    Copy-Item -Path (Join-Path $PluginRoot "$PluginSlug.php") -Destination $StageDir
    Copy-Item -Path (Join-Path $PluginRoot "uninstall.php") -Destination $StageDir

    $optionalFiles = @("readme.txt", "README.md", "LICENSE")
    foreach ($optFile in $optionalFiles) {
        $optPath = Join-Path $PluginRoot $optFile
        if (Test-Path -Path $optPath -PathType Leaf) {
            Copy-Item -Path $optPath -Destination $StageDir
        }
    }

    # Salin folder-folder modul produksi
    $productionDirs = @("admin", "includes", "languages")
    foreach ($dir in $productionDirs) {
        $dirPath = Join-Path $PluginRoot $dir
        if (Test-Path -Path $dirPath -PathType Container) {
            Copy-Item -Path $dirPath -Destination $StageDir -Recurse -Force
        }
    }

    # Bersihkan file sampah OS / editor dari staging
    Get-ChildItem -Path $StageDir -Recurse -Include ".DS_Store", "*.swp", "*~", "Thumbs.db" -Force -ErrorAction SilentlyContinue | Remove-Item -Force

    # 5. Buat direktori output jika belum ada
    if (-not (Test-Path -Path $OutputDir -PathType Container)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }

    $TargetZip = Join-Path $OutputDir $ZipFilename
    $LatestZip = Join-Path $OutputDir $LatestZipFilename

    # Hapus file ZIP lama jika ada
    if (Test-Path -Path $TargetZip) { Remove-Item -Path $TargetZip -Force }
    if (Test-Path -Path $LatestZip) { Remove-Item -Path $LatestZip -Force }

    Log-Success "Membuat arsip ZIP..."

    # Gunakan Compress-Archive bawaan PowerShell (optimal compression)
    Compress-Archive -Path $StageDir -DestinationPath $TargetZip -CompressionLevel Optimal

    # Salin sebagai versi latest standar (wp-root-guard.zip)
    Copy-Item -Path $TargetZip -Destination $LatestZip -Force

    # 6. Hitung Total Berkas & Ukuran
    $zipFileInfo = Get-Item -Path $TargetZip
    $fileSizeKB = [math]::Round($zipFileInfo.Length / 1KB, 1)

    Log-Success "Packaging berhasil diselesaikan! 🎉"
    Write-Host ""
    Write-Host "Ringkasan Paket:" -ForegroundColor Green
    Write-Host "----------------------------------------------------"
    Write-Host "  Berkas Utama : $TargetZip"
    Write-Host "  Salinan Rilis: $LatestZip"
    Write-Host "  Ukuran Paket : ${fileSizeKB} KB"
    Write-Host "  Struktur Root: $PluginSlug/"
    Write-Host "----------------------------------------------------"
    Write-Host ""
    Write-Host "File siap diunggah melalui:" -ForegroundColor Cyan
    Write-Host "WP Admin -> Plugins -> Add New -> Upload Plugin" -ForegroundColor White
}
finally {
    # Bersihkan direktori staging sementara
    if (Test-Path -Path $TempBase) {
        Remove-Item -Path $TempBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

param(
    [Parameter(Mandatory = $true)][string]$Certificado,
    [Parameter(Mandatory = $true)][string]$Senha,
    [string]$Exe = "dist\scanner.exe",
    [string]$Carimbo = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "x64" } | Sort-Object FullName -Descending | Select-Object -First 1

if (-not $signtool) {
    Write-Host "signtool.exe nao encontrado. Instale o Windows SDK:" -ForegroundColor Yellow
    Write-Host "  winget install Microsoft.WindowsSDK" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $Exe)) { Write-Host "Nao achei $Exe" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $Certificado)) { Write-Host "Nao achei $Certificado" -ForegroundColor Red; exit 1 }

Write-Host "Assinando $Exe" -ForegroundColor Cyan
& $signtool.FullName sign /f $Certificado /p $Senha /fd SHA256 /tr $Carimbo /td SHA256 /d "Scanner Filadelfia" $Exe
if ($LASTEXITCODE -ne 0) { Write-Host "Falha ao assinar" -ForegroundColor Red; exit 1 }

Write-Host "Conferindo a assinatura" -ForegroundColor Cyan
& $signtool.FullName verify /pa /v $Exe
if ($LASTEXITCODE -ne 0) { Write-Host "A assinatura nao passou na verificacao" -ForegroundColor Red; exit 1 }

Write-Host "Assinado com sucesso. Envie tambem o arquivo novo para a Microsoft em" -ForegroundColor Green
Write-Host "https://www.microsoft.com/en-us/wdsi/filesubmission" -ForegroundColor Green

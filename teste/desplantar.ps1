#Requires -RunAsAdministrator
param([string]$Termo = "")

$ErrorActionPreference = "SilentlyContinue"
$aqui = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Termo) {
  $p = Join-Path $aqui "plantio.json"
  if (Test-Path $p) { $Termo = (Get-Content $p -Raw | ConvertFrom-Json).termo }
}
if (-not $Termo) { Write-Host "Informe -Termo"; exit 1 }

$perfil = $env:USERPROFILE
$downloads = Join-Path $perfil "Downloads"
$desktop = [Environment]::GetFolderPath("Desktop")
$documentos = [Environment]::GetFolderPath("MyDocuments")
$temp = $env:TEMP

Get-Process | Where-Object { $_.Name -like "$($Termo)_*" } | Stop-Process -Force
Get-Process cmd | Where-Object { $_.MainWindowTitle -like "plantio*" } | Stop-Process -Force
schtasks /delete /tn "$($Termo)Updater" /f | Out-Null
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "$($Termo)Start"
Remove-Item Env:\PLANTIO_MARCA

@(
  (Join-Path $downloads "$($Termo)_loader.exe"),
  (Join-Path $downloads "$($Termo)_pack.zip"),
  (Join-Path $downloads "scanner_$($Termo).exe"),
  (Join-Path $desktop "notas.txt"),
  (Join-Path $desktop "$($Termo).lnk"),
  (Join-Path $documentos "foto.jpg"),
  (Join-Path $documentos "script.lua"),
  (Join-Path $temp "xk9f2m1pq7zt.exe"),
  (Join-Path $temp "$($Termo)_mem.exe"),
  (Join-Path $temp "plantio_zip"),
  (Join-Path $env:APPDATA "discord\Cache\Cache_Data\f_plantio")
) | ForEach-Object { if (Test-Path $_) { Remove-Item $_ -Recurse -Force; Write-Host "removido: $_" } }

Write-Host "Pronto. O item da lixeira e o registro no Amcache e no Prefetch ficam, porque sao rastro real de teste; esvazie a lixeira se quiser."

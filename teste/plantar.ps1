#Requires -RunAsAdministrator
param(
  [string]$Termo = "",
  [string]$Dominio = "",
  [string]$Assinaturas = ""
)

$ErrorActionPreference = "Continue"
$aqui = Split-Path -Parent $MyInvocation.MyCommand.Path

function LeLista($caminho) {
  if (-not $caminho -or -not (Test-Path $caminho)) { return $null }
  try { return Get-Content $caminho -Raw | ConvertFrom-Json } catch { return $null }
}

$lista = LeLista $Assinaturas
if (-not $lista) { $lista = LeLista (Join-Path $aqui "..\assinaturas.json") }
if (-not $lista) { $lista = LeLista (Join-Path $aqui "..\dist\assinaturas.json") }
if (-not $Termo) {
  if ($lista -and $lista.marcas -and $lista.marcas.Count -gt 0) { $Termo = [string]$lista.marcas[0] }
  else { $Termo = "eulen" }
}
if (-not $Dominio) {
  if ($lista -and $lista.dominios -and $lista.dominios.Count -gt 0) { $Dominio = [string]$lista.dominios[0] }
  else { $Dominio = "eulen.cc" }
}
$Termo = $Termo.ToLower() -replace "[^a-z0-9]", ""
if ($Termo.Length -lt 3) { $Termo = "eulen" }

$perfil = $env:USERPROFILE
$downloads = Join-Path $perfil "Downloads"
$desktop = [Environment]::GetFolderPath("Desktop")
$documentos = [Environment]::GetFolderPath("MyDocuments")
$temp = $env:TEMP
$cmd = Join-Path $env:SystemRoot "System32\cmd.exe"
$evidencias = @()
$aleatorio = "xk9f2m1pq7zt"

function Registra($id, $descricao, $tipo, $precisa, $severidade) {
  $script:evidencias += [ordered]@{ id = $id; descricao = $descricao; tipo = $tipo; precisa = @($precisa); severidade = $severidade }
  Write-Host ("  [{0,2}] {1}" -f $id, $descricao)
}

Write-Host "Plantando evidencias com o termo '$Termo' e o dominio '$Dominio'"
Write-Host ""

$loader = Join-Path $downloads "$($Termo)_loader.exe"
Copy-Item $cmd $loader -Force
Registra 1 "Executavel com nome de cheat em Downloads" "achado" @($Termo, "_loader.exe") "CRITICO"

$pastaZip = Join-Path $temp "plantio_zip"
New-Item -ItemType Directory -Force $pastaZip | Out-Null
Copy-Item $cmd (Join-Path $pastaZip "menu.exe") -Force
Set-Content (Join-Path $pastaZip "leia.txt") "pacote de teste"
$zip = Join-Path $downloads "$($Termo)_pack.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $pastaZip "*") -DestinationPath $zip -Force
Registra 2 "Zip em Downloads com programa dentro" "achado" @("$($Termo)_pack.zip", "menu.exe") "ALERTA"

$disfarce = Join-Path $desktop "notas.txt"
$bytes = New-Object byte[] 4096
$bytes[0] = 0x4D; $bytes[1] = 0x5A
[IO.File]::WriteAllBytes($disfarce, $bytes)
Registra 3 "Executavel disfarcado de .txt na area de trabalho" "achado" @("disfarcado", "notas.txt") "CRITICO"

$foto = Join-Path $documentos "foto.jpg"
Set-Content $foto "nao e uma foto"
Set-Content -Path $foto -Stream "$($Termo).exe" -Value "conteudo escondido"
Registra 4 "Fluxo alternativo (ADS) com nome de cheat em foto.jpg" "achado" @($Termo, "foto.jpg") "ALERTA"

$lnk = Join-Path $desktop "$($Termo).lnk"
$shell = New-Object -ComObject WScript.Shell
$atalho = $shell.CreateShortcut($lnk)
$atalho.TargetPath = Join-Path $env:APPDATA "$($Termo)\menu.exe"
$atalho.Save()
Registra 5 "Atalho apontando para pasta de cheat apagada" "achado" @($Termo, "atalho") "CRITICO"

schtasks /create /tn "$($Termo)Updater" /tr "`"$loader`"" /sc onlogon /f | Out-Null
Registra 6 "Tarefa agendada com nome de cheat" "achado" @("$($Termo)updater") "ALERTA"

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "$($Termo)Start" -Value "`"$loader`"" -PropertyType String -Force | Out-Null
Registra 7 "Entrada de inicializacao automatica com nome de cheat" "achado" @("$($Termo)start") "ALERTA"

Start-Process -FilePath $loader -ArgumentList "/k", "title plantio_loader" -WindowStyle Hidden
Registra 8 "Processo com nome de cheat rodando agora" "processo" @($Termo, "_loader") ""

$rand = Join-Path $temp "$aleatorio.exe"
Copy-Item $cmd $rand -Force
Registra 9 "Executavel com nome aleatorio no Temp" "achado" @("nome aleatorio", $aleatorio) "ALERTA"

$lua = Join-Path $documentos "script.lua"
Set-Content $lua "local menu = '$Termo menu v3'`nprint(menu)"
Registra 10 "String de cheat dentro de um .lua" "achado" @($Termo, "script.lua") "ALERTA"

$discord = Join-Path $env:APPDATA "discord\Cache\Cache_Data"
New-Item -ItemType Directory -Force $discord | Out-Null
Set-Content (Join-Path $discord "f_plantio") "convite: https://discord.gg/$Termo baixa ai o $Termo menu"
Registra 11 "Convite de cheat no cache do Discord" "achado" @($Termo, "discord") "ALERTA"

$evasao = Join-Path $downloads "scanner_$($Termo).exe"
Copy-Item $cmd $evasao -Force
Registra 12 "Cheat renomeado para comecar com 'scanner' (teste de evasao)" "achado" @("scanner_$($Termo)") "CRITICO"

Resolve-DnsName $Dominio -ErrorAction SilentlyContinue | Out-Null
nslookup $Dominio 2>$null | Out-Null
Registra 13 "Dominio de cheat no cache DNS" "achado" @($Dominio) "CRITICO"

Registra 14 "Prefetch do loader que rodou" "achado" @($Termo, "prefetch") "CRITICO"

$velho = Join-Path $downloads "$($Termo)_old.rar"
Set-Content $velho "rar falso"
Add-Type -AssemblyName Microsoft.VisualBasic
[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($velho, 'OnlyErrorDialogs', 'SendToRecycleBin')
Registra 15 "Arquivo com nome de cheat na lixeira" "achado" @($Termo, "_old") "ALERTA"

$mem = Join-Path $temp "$($Termo)_mem.exe"
Copy-Item $cmd $mem -Force
[IO.File]::AppendAllText($mem, "plantio quebra a assinatura")
$env:PLANTIO_MARCA = "$Termo menu injected aimbot esp"
Start-Process -FilePath $mem -ArgumentList "/k", "title plantio_mem" -WindowStyle Hidden
Registra 17 "String de cheat na memoria de processo sem assinatura valida" "achado" @($Termo, "memoria") "CRITICO"

schtasks /run /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" 2>$null | Out-Null
Registra 16 "Loader registrado no Amcache (pode levar alguns minutos para o Windows gravar)" "achado" @($Termo, "amcache") "CRITICO"

Start-Sleep -Seconds 3

$saida = Join-Path $aqui "plantio.json"
[ordered]@{ termo = $Termo; dominio = $Dominio; gerado_em = (Get-Date).ToString("s"); evidencias = $evidencias } | ConvertTo-Json -Depth 5 | Set-Content $saida -Encoding UTF8
Write-Host ""
Write-Host "Lista gravada em $saida"
Write-Host "Agora rode o scanner (checagem completa) e depois: verificar.exe plantio.json <relatorio>.json"

package main

import (
	"strings"
	"time"
)

const (
	CenarioSuspeito = "suspeito"
	CenarioLimpo    = "limpo"
	CenarioAtivo    = "ativo"
	CenarioRastros  = "rastros"
	CenarioFechou   = "fechou"
)

func ehSimulacao(modo string) bool {
	return modo == CenarioSuspeito || modo == CenarioLimpo || modo == CenarioAtivo || modo == CenarioRastros || modo == CenarioFechou
}

func processosSimulados(c *Contexto, comCheat bool) {
	r := c.R
	base := []struct {
		pid                int
		nome, caminho, pai string
	}{
		{4, "System", "", ""},
		{812, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "services.exe"},
		{1204, "explorer.exe", "C:\\Windows\\explorer.exe", "userinit.exe"},
		{2210, "Discord.exe", "C:\\Users\\jogador\\AppData\\Local\\Discord\\app-1.0.9200\\Discord.exe", "explorer.exe"},
		{2388, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "explorer.exe"},
		{3010, "steam.exe", "C:\\Program Files (x86)\\Steam\\steam.exe", "explorer.exe"},
		{3320, "NVDisplay.Container.exe", "C:\\Program Files\\NVIDIA Corporation\\Display.NvContainer\\NVDisplay.Container.exe", "services.exe"},
		{3510, "MsMpEng.exe", "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25070.5-0\\MsMpEng.exe", "services.exe"},
		{4100, "Spotify.exe", "C:\\Users\\jogador\\AppData\\Roaming\\Spotify\\Spotify.exe", "explorer.exe"},
		{5120, "obs64.exe", "C:\\Program Files\\obs-studio\\bin\\64bit\\obs64.exe", "explorer.exe"},
		{6008, "FiveM.exe", "C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.exe", "explorer.exe"},
		{6210, "FiveM_b3095_GTAProcess.exe", "C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app\\FiveM_b3095_GTAProcess.exe", "FiveM.exe"},
		{6390, "FiveM_b3095_DumpServer", "C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app\\FiveM_b3095_DumpServer.exe", "FiveM.exe"},
		{7001, "RuntimeBroker.exe", "C:\\Windows\\System32\\RuntimeBroker.exe", "svchost.exe"},
		{7420, "conhost.exe", "C:\\Windows\\System32\\conhost.exe", "cmd.exe"},
	}
	for _, p := range base {
		situacao := ""
		if strings.Contains(strings.ToLower(p.nome), "fivem") {
			situacao = "fivem"
		}
		r.Processo(p.pid, p.nome, p.caminho, situacao, p.pai)
	}
	if comCheat {
		r.Add(Critico, "Processo RODANDO bate com assinatura 'eulen': eulen_loader.exe (PID 8102)", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe")
		r.Processo(8102, "eulen_loader.exe", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe", "cheat", "explorer.exe")
		r.Add(Alerta, "Processo com nome aleatorio rodado da pasta TEMP: a9f31c7d4b.exe (PID 8140)", "C:\\Users\\jogador\\AppData\\Local\\Temp\\a9f31c7d4b.exe")
		r.Processo(8140, "a9f31c7d4b.exe", "C:\\Users\\jogador\\AppData\\Local\\Temp\\a9f31c7d4b.exe", "suspeito", "eulen_loader.exe")
	}
	r.Linha("FiveM FiveM_b3095_GTAProcess.exe (PID 6210) com %d modulos carregados", map[bool]int{true: 214, false: 198}[comCheat])
	for _, m := range []struct{ nome, caminho, sit string }{
		{"ntdll.dll", "C:\\Windows\\SYSTEM32\\ntdll.dll", ""},
		{"CitizenGame.dll", "C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app\\CitizenGame.dll", ""},
		{"citizen-scripting-lua.dll", "C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app\\citizen-scripting-lua.dll", ""},
		{"DiscordHook64.dll", "C:\\Users\\jogador\\AppData\\Local\\Discord\\app-1.0.9200\\modules\\discord_hook-1\\discord_hook\\DiscordHook64.dll", ""},
		{"nvngx_dlss.dll", "C:\\Windows\\System32\\DriverStore\\FileRepository\\nv_dispi.inf_amd64_1f2a\\nvngx_dlss.dll", ""},
		{"GameOverlayRenderer64.dll", "C:\\Program Files (x86)\\Steam\\GameOverlayRenderer64.dll", ""},
	} {
		r.Modulo(6210, m.nome, m.caminho, m.sit)
	}
	if comCheat {
		r.Add(Critico, "Modulo INJETADO no FiveM bate com assinatura 'eulen': eulen.dll", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen.dll")
		r.Modulo(6210, "eulen.dll", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen.dll", "cheat")
		r.Add(Alerta, "Modulo carregado no FiveM de pasta fora do padrao: d3d11hook.dll", "C:\\Users\\jogador\\AppData\\Roaming\\hk\\d3d11hook.dll")
		r.Modulo(6210, "d3d11hook.dll", "C:\\Users\\jogador\\AppData\\Roaming\\hk\\d3d11hook.dll", "suspeito")
	} else {
		r.Ok("Nenhum modulo de pasta desconhecida no FiveM (PID 6210). Cheats com manual map nao aparecem aqui")
	}
}

func pausaSimulada(d time.Duration) {
	time.Sleep(d)
}

func etapasSimuladas(cenario string) []Etapa {
	switch cenario {
	case CenarioLimpo:
		return etapasSimuladasLimpo()
	case CenarioAtivo:
		return etapasSimuladasAtivo()
	case CenarioRastros:
		return etapasSimuladasRastros()
	case CenarioFechou:
		return etapasSimuladasFechou()
	}
	return etapasSimuladasSuspeito()
}

func cabecalhoSimulado(c *Contexto, sujo bool) {
	r := c.R
	r.Secao("SISTEMA")
	r.Linha("MODO SIMULADO: nenhum dado real deste computador foi lido")
	instalacao := time.Now().Add(-45 * 24 * time.Hour)
	if sujo {
		instalacao = time.Now().Add(-38 * time.Hour)
	}
	c.Instalacao = instalacao
	r.Sistema_("Modo", "SIMULACAO ("+map[bool]string{true: "PC suspeito", false: "PC limpo"}[sujo]+")")
	r.Sistema_("Windows", "Windows 11 Pro 24H2 (build 26100.3194)")
	r.Sistema_("Usuario atual", "jogador")
	r.Sistema_("Instalacao do Windows", formataHora(instalacao))
	r.Sistema_("Ultimo boot", formataHora(time.Now().Add(-3*time.Hour))+" (ligado ha 3h0m0s)")
	r.Sistema_("Hora do sistema", formataHora(time.Now()))
	r.Sistema_("Perfis de usuario", "jogador (hive carregada); Administrador (sem sessao aberta)")
	pausaSimulada(250 * time.Millisecond)
}

func etapasSimuladasSuspeito() []Etapa {
	return []Etapa{
		{"Sistema e integridade de codigo", func(c *Contexto) {
			r := c.R
			cabecalhoSimulado(c, true)
			r.Add(Alerta, "Windows instalado ha menos de 3 dias", "Formatacao recente apaga todo o historico. Instalado em "+formataHora(c.Instalacao))
			r.Add(Critico, "Modo TESTSIGNING ativo", "Permite carregar drivers de kernel sem assinatura. Usado por cheats de kernel e spoofers")
			r.Add(Critico, "Lista de bloqueio de drivers vulneraveis DESATIVADA", "Ninguem desliga isso sem querer. Necessario para carregar drivers vulneraveis (BYOVD) usados por mapeadores de cheat")
			r.Add(Critico, "Prefetch DESATIVADO no registro", "EnablePrefetcher=0. Impede o Windows de registrar programas executados")
			r.Add(Info, "Secure Boot desligado", "Nao e prova de nada, mas facilita drivers nao assinados e spoofers de BIOS")
			r.Ok("HVCI (integridade de memoria) ligado")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		{"Servicos de rastreio e protecao", func(c *Contexto) {
			r := c.R
			r.Secao("SERVICOS DO WINDOWS (rastreio e protecao)")
			r.Linha("%-24s %-10s inicio: %-11s %s", "EventLog", "rodando", "automatico", "Log de eventos do Windows")
			r.Add(Critico, "Servico SysMain esta DESATIVADO", "Superfetch/Prefetch. Desligar apaga o registro de programas executados")
			r.Add(Critico, "Servico PcaSvc esta DESATIVADO", "Assistente de compatibilidade. Grava caminho de cada exe executado")
			r.Add(Alerta, "Servico DPS esta PARADO", "Diagnostic Policy Service. Base do SRUM/PcaSvc, cheaters desligam para nao registrar exe")
			r.Add(Alerta, "Servico Dnscache esta PARADO", "Cache de DNS. Desligar limpa o historico de sites do loader do cheat")
			r.Ok("Servico Schedule rodando normalmente")
			pausaSimulada(280 * time.Millisecond)
		}, false},
		{"Windows Defender", func(c *Contexto) {
			r := c.R
			r.Secao("WINDOWS DEFENDER")
			r.Add(Critico, "Defender desativado por politica (DisableAntiSpyware)", `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender -> DisableAntiSpyware=1. Ferramentas tipo Defender Control gravam isso`)
			r.Add(Critico, "Exclusao no Defender: C:\\Users\\jogador\\AppData\\Local\\Temp\\ldr", "Exclusao de paths no Defender. Loaders de cheat pedem para excluir a pasta antes de rodar")
			r.Add(Alerta, "Exclusao no Defender: C:\\Users\\jogador\\AppData\\Local\\FiveM", "Exclusao na pasta do jogo. Loaders de cheat pedem para excluir a pasta antes de rodar")
			r.Add(Critico, "Historico do Defender tem 3 ameaca(s)", "HackTool:Win32/Injector  (CHEGOU A EXECUTAR)\nHackTool:Win64/AutoKMS\nTrojan:Win32/Wacatac.B!ml")
			r.Add(Info, "Tamper Protection do Defender desligada", "Permite desligar o Defender por registro/script")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		{"Logs de eventos", func(c *Contexto) {
			r := c.R
			r.Secao("LOGS DE EVENTOS DO WINDOWS")
			r.Add(Critico, "Log de SEGURANCA foi LIMPO em "+formataHora(time.Now().Add(-26*time.Hour)), "Evento 1102, usuario: jogador. O evento 1102 sobrevive a limpeza justamente para marcar quem limpou")
			r.Add(Critico, "Log 'Microsoft-Windows-PowerShell/Operational' foi LIMPO em "+formataHora(time.Now().Add(-25*time.Hour)), "Evento 104, usuario: jogador")
			r.Linha("%-58s registros: %-7d mais antigo: %s  limite: %d MB", "System", 412, formataHora(time.Now().Add(-26*time.Hour)), 20)
			r.Add(Alerta, "Log 'System' so tem eventos das ultimas 26h0m0s", "Windows instalado em "+formataHora(c.Instalacao)+". Pode ser limpeza ou rotacao por tamanho (limite 20 MB, 412 registros)")
			r.Add(Alerta, "1 alteracao(oes) manual(is) de hora nos ultimos 30 dias", formataHora(time.Now().Add(-27*time.Hour))+" por jogador (de 2026-09-08T02:11:04 para 2026-09-06T19:00:00)")
			r.Add(Critico, "Driver VULNERAVEL instalado como servico: iqvw64e.sys", formataHora(time.Now().Add(-30*time.Hour))+"  nvdisp2  [kernel driver]  C:\\Users\\jogador\\AppData\\Local\\Temp\\iqvw64e.sys")
			r.Add(Critico, "2 script(s) PowerShell de ocultacao/cheat registrados", formataHora(time.Now().Add(-26*time.Hour))+"  [limpa log de eventos]  wevtutil cl Security; wevtutil cl System\n"+formataHora(time.Now().Add(-26*time.Hour))+"  [desliga o Defender]  Set-MpPreference -DisableRealtimeMonitoring $true")
			pausaSimulada(350 * time.Millisecond)
		}, false},
		{"ETW / kernel", func(c *Contexto) {
			r := c.R
			r.Secao("ETW / KERNEL (rastreamento do proprio Windows)")
			r.Linha("164 sessoes de rastreamento ETW ativas no sistema")
			r.Add(Critico, "1 sessao(oes) ETW essencial(is) do Windows PARADA(S)", "eventlog-security (canal ETW que alimenta o log de Seguranca)\nParar essas sessoes faz o Windows deixar de gravar eventos sem que o log pareca limpo. Tecnica de ocultacao mais fina que apagar o log")
			r.Add(Critico, "Windows BLOQUEOU um driver/binario nao assinado", "\\Device\\HarddiskVolume3\\Users\\jogador\\AppData\\Local\\Temp\\drv.sys\n"+formataHora(time.Now().Add(-30*time.Hour))+"\nEvento 3033 do Code Integrity. O sistema recusou carregar codigo sem assinatura valida. E o rastro classico de tentativa de carregar driver de cheat")
			r.Add(Alerta, "Sessao ETW de seguranca foi mexida: DefenderApiLogger", formataHora(time.Now().Add(-27*time.Hour))+"  evento 3  DefenderApiLogger\nParar a sessao de rastreamento do antivirus ou do anticheat e forma de cegar a protecao sem desinstalar nada")
			r.Progresso("Iniciando captura ao vivo do kernel por 20s")
			pausaSimulada(700 * time.Millisecond)
			r.Progresso("Gravando eventos do kernel (ImageLoad, ProcessStart, DNS). Faltam 12s")
			pausaSimulada(700 * time.Millisecond)
			r.Linha("Captura do kernel: 4812 eventos em 21s (3944 carregamentos de imagem, 61 processos novos, 88 consultas DNS)")
			r.Ok("Teste ativo do ETW passou: o kernel registrou os 10 processos que o scanner iniciou de proposito")
			r.Add(Critico, "Kernel registrou carregamento de DLL/EXE com assinatura 'eulen'", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen.dll\nCapturado ao vivo pelo ETW durante a checagem, mesmo que o arquivo tenha sido apagado depois")
			r.Add(Critico, "Consulta DNS a dominio de cheat ('eulen.cc') durante a checagem: api.eulen.cc", "Capturada ao vivo pelo ETW. Loader de cheat consulta o servidor de licenca de tempos em tempos, entao isso indica cheat ativo agora")
			pausaSimulada(400 * time.Millisecond)
		}, false},
		{"Historico de execucao no registro", func(c *Contexto) {
			r := c.R
			r.Secao("HISTORICO DE EXECUCAO (registro do Windows)")
			r.Linha("Entradas encontradas: BAM=9  UserAssist=0  PcaSvc Store=0  MuiCache=61  RecentDocs=14")
			r.Add(Alerta, "BAM com poucas entradas (9)", "Pode ter sido limpo recentemente")
			r.Add(Alerta, "UserAssist vazio", "Historico de programas abertos pelo Explorer foi limpo ou desativado")
			r.Add(Alerta, "Compatibility Assistant Store vazio", "Historico do PcaSvc limpo (ou servico parado ha muito tempo)")
			r.Add(Critico, "Executado (BAM) bate com assinatura 'eulen': eulen_loader.exe", formataHora(time.Now().Add(-28*time.Hour))+"  usuario: jogador\nC:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe")
			r.Add(Alerta, "Executavel rodado da pasta TEMP (BAM)", formataHora(time.Now().Add(-29*time.Hour))+"  usuario: jogador\nC:\\Users\\jogador\\AppData\\Local\\Temp\\a9f31c7d4b.exe")
			r.Add(Critico, "Comando de ocultacao na caixa Executar (jogador): limpa log de eventos", "wevtutil cl Security")
			r.Add(Critico, "Historico PowerShell de jogador tem 4 comando(s) de ocultacao/cheat", "[limpa log de eventos] Clear-EventLog -LogName Security\n[apaga o journal USN] fsutil usn deletejournal /d C:\n[desliga o Defender] Set-MpPreference -DisableRealtimeMonitoring $true\n[mexe no Prefetch] Remove-Item C:\\Windows\\Prefetch\\* -Force")
			pausaSimulada(320 * time.Millisecond)
		}, false},
		{"Prefetch", func(c *Contexto) {
			r := c.R
			r.Secao("PREFETCH (programas executados)")
			r.Linha("31 arquivos .pf em C:\\Windows\\Prefetch")
			r.Add(Critico, "Prefetch foi LIMPO nas ultimas 24h", "Todos os 31 arquivos .pf sao posteriores a "+formataHora(time.Now().Add(-20*time.Hour))+", mas o Windows foi instalado em "+formataHora(c.Instalacao))
			pausaSimulada(220 * time.Millisecond)
		}, false},
		{"Artefatos do Windows (ShimCache, crashes, atalhos)", func(c *Contexto) {
			r := c.R
			r.Secao("ARTEFATOS DO WINDOWS (ShimCache, crashes, atalhos)")
			r.Linha("AppCompatCache (ShimCache): 682 executaveis registrados pelo Windows")
			r.Add(Critico, "ShimCache registrou execucao de arquivo com assinatura 'eulen': eulen_loader.exe", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe\nmodificado: "+formataHora(time.Now().Add(-29*time.Hour))+"\nO ShimCache guarda o caminho mesmo que o arquivo tenha sido apagado e o Prefetch limpo")
			r.Add(Alerta, "ShimCache tem 2 executavel(is) de pasta suspeita", formataHora(time.Now().Add(-29*time.Hour))+"  C:\\Users\\jogador\\AppData\\Local\\Temp\\a9f31c7d4b.exe  (com nome aleatorio rodado da pasta TEMP)")
			r.Linha("Relatorios de erro e dumps do Windows: 91 arquivos analisados")
			r.Add(Critico, "Relatorio de erro do Windows de um programa com assinatura 'redengine'", "C:\\Users\\jogador\\Downloads\\redengine_v4.exe\n"+formataHora(time.Now().Add(-6*24*time.Hour))+"\nem: C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\AppCrash_redengine_v4.exe_1a2b\\Report.wer\nO Windows guarda o crash mesmo depois do programa ser apagado. Cheat trava com frequencia e deixa esse rastro")
			r.Linha("Atalhos e jump lists analisados: 44")
			r.Add(Critico, "Atalho (.lnk) aponta para arquivo com assinatura 'eulen'", "C:\\Users\\jogador\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\eulen_loader.lnk\n"+formataHora(time.Now().Add(-28*time.Hour))+"\n...C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe...\nO atalho guarda o caminho do arquivo original mesmo depois dele ser apagado")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		{"Arquivos recentes e lixeira", func(c *Contexto) {
			r := c.R
			r.Secao("ARQUIVOS RECENTES E LIXEIRA")
			r.Linha("Recentes de jogador: 0 atalhos, ultimo em desconhecido")
			r.Add(Alerta, "Pasta de recentes de jogador esta vazia", "Limpeza manual ou por ferramenta (CCleaner e similares)")
			r.Add(Critico, "Item na LIXEIRA de jogador bate com assinatura 'hwid spoofer'", "C:\\Users\\jogador\\Downloads\\HWID Spoofer v4.rar  (deletado em "+formataHora(time.Now().Add(-24*time.Hour))+")")
			r.Add(Info, "Executaveis/arquivos compactados na lixeira de jogador (C:\\)", formataHora(time.Now().Add(-24*time.Hour))+"  C:\\Users\\jogador\\Downloads\\loader_v2.rar")
			pausaSimulada(260 * time.Millisecond)
		}, false},
		{"Processos, handles, overlay e drivers", func(c *Contexto) {
			r := c.R
			r.Secao("PROCESSOS EM EXECUCAO (analise ponto a ponto)")
			r.Linha("184 processos em execucao")
			processosSimulados(c, true)
			r.Secao("DRIVERS DE KERNEL CARREGADOS")
			r.Linha("178 drivers carregados")
			r.Add(Critico, "Driver VULNERAVEL carregado de fora do sistema: iqvw64e.sys", "C:\\Users\\jogador\\AppData\\Local\\Temp\\iqvw64e.sys\nDriver da lista BYOVD carregado de pasta fora do Windows/Program Files. Padrao de mapeador de cheat")
			pausaSimulada(340 * time.Millisecond)
		}, false},
		etapaSimuladaSimples("Integridade do jogo (FiveM e GTA V)", "INTEGRIDADE DO JOGO (FiveM e GTA V)", func(c *Contexto) {
			c.R.Ok("Windows rodando direto no hardware, nao em maquina virtual")
			c.R.Linha("FiveM de jogador em C:\\Users\\jogador\\Downloads\\FiveM.app")
			c.R.Add(Alerta, "FiveM instalado em pasta fora do padrao", "C:\\Users\\jogador\\Downloads\\FiveM.app\nO instalador oficial coloca o FiveM em AppData\\Local\\FiveM. Instalacao em Downloads, Desktop ou Temp costuma indicar copia baixada pronta de outro lugar, e nao instalacao pelo site oficial")
			c.R.Linha("214 arquivos do FiveM conferidos em 41s")
			c.R.Add(Critico, "Arquivo do jogo ASSINADO MAS ALTERADO: citizen-scripting-lua.dll", "C:\\Users\\jogador\\Downloads\\FiveM.app\\citizen-scripting-lua.dll\n"+formataHora(time.Now().Add(-30*time.Hour))+"\nO arquivo foi modificado depois de assinado pelo fabricante. E exatamente o que acontece quando alguem troca uma dll do jogo por uma versao com cheat embutido")
			c.R.Linha("GTA V em D:\\SteamLibrary\\steamapps\\common\\Grand Theft Auto V")
			c.R.Add(Alerta, "DLL de carregamento de mod na pasta do GTA: dinput8.dll", "D:\\SteamLibrary\\steamapps\\common\\Grand Theft Auto V\\dinput8.dll  (412 KB, "+formataHora(time.Now().Add(-31*time.Hour))+")\ncarregador de mods ASI (padrao do ScriptHookV e de menus)\nO GTA original nao traz essa dll")
			c.R.Add(Alerta, "2 plugin(s) .asi instalado(s) na pasta do GTA", "D:\\...\\Grand Theft Auto V\\OpenIV.asi  (1204 KB)\nD:\\...\\Grand Theft Auto V\\NativeTrainer.asi  (208 KB)")
		}),
		etapaSimuladaSimples("Conteudo dos pacotes baixados", "CONTEUDO DOS PACOTES BAIXADOS (zip, rar, 7z)", func(c *Contexto) {
			c.R.Linha("3 pacote(s) compactado(s) para abrir e conferir por dentro")
			c.R.Add(Critico, "Dentro de loader_v2.rar tem arquivo com nome de cheat ('eulen'): eulen_loader.exe", "C:\\Users\\jogador\\Downloads\\loader_v2.rar\neulen_loader.exe  (3120 KB)\nO scanner abriu o pacote e leu a lista de arquivos de dentro dele")
			c.R.Add(Critico, "citizen com agua.zip tem 2 programa(s)/script(s) dentro", "C:\\Users\\jogador\\Downloads\\citizen com agua.zip\ncitizen-scripting-lua.dll  [biblioteca]  8336 KB\ninstalar.bat  [script de comando]  2 KB\nPacote de mod visual normalmente so tem .rpf, .ytd, .ydr, imagem e texto. Programa, dll, driver ou script dentro de um pacote de mod e o jeito mais comum de entregar cheat")
			c.R.Add(Info, "Conteudo de SOM PVP TEQUINHO.rar: 41 arquivo(s), nada suspeito", "C:\\Users\\jogador\\Downloads\\SOM PVP TEQUINHO.rar\nsounds/weapons/ak47.wav  (0 KB)\nsounds/weapons/pistol.wav  (0 KB)\nleiame.txt  (0 KB)")
		}),
		etapaSimuladaSimples("Hardware (DMA, KMBox, aim assist)", "HARDWARE (placa DMA, KMBox, dispositivos de aim assist)", func(c *Contexto) {
			c.R.Linha("221 dispositivos PCI/USB/HID conhecidos pelo Windows (conectados agora ou no passado)")
			c.R.Add(Critico, "Placa DMA/FPGA detectada ('xilinx'): Xilinx Development System", "PCI\\VEN_10EE&DEV_7022\\4&1a2b\nconectado agora\nPlaca DMA le a memoria do jogo de um segundo PC. Nao existe uso comum disso em PC gamer")
		}),
		{"FiveM", func(c *Contexto) {
			r := c.R
			r.Secao("FIVEM")
			r.Linha("Instalacao de jogador: C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app")
			r.Add(Alerta, "Plugin carregado pelo FiveM: openvhook.asi", "C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app\\plugins\\openvhook.asi\nQualquer .asi/.dll nessa pasta e injetado no jogo. Confirmar se e mod visual legitimo")
			r.Add(Critico, "Log do FiveM menciona assinatura de cheat", "[eulen] [   482375] Loading module: eulen.dll")
			pausaSimulada(240 * time.Millisecond)
		}, false},
		{"Cache DNS e journal USN", func(c *Contexto) {
			r := c.R
			r.Secao("CACHE DNS (sites acessados desde o boot)")
			r.Linha("3 nomes unicos no cache DNS")
			r.Add(Critico, "Cache DNS tem dominio de cheat ('eulen.cc'): api.eulen.cc", "O PC resolveu esse dominio desde o ultimo boot")
			r.Add(Alerta, "Cache DNS praticamente vazio com o PC ligado ha mais de 30 min", "ipconfig /flushdns ou servico Dnscache parado")
			r.Secao("JOURNAL USN (historico de alteracoes do disco)")
			r.Add(Alerta, "Journal USN de C: foi recriado em "+formataHora(time.Now().Add(-25*time.Hour)), "Windows instalado em "+formataHora(c.Instalacao)+". Journal recriado depois da instalacao indica 'fsutil usn deletejournal' (ou chkdsk/erro de disco)")
			pausaSimulada(260 * time.Millisecond)
		}, false},
		{"Historico dos navegadores", func(c *Contexto) {
			r := c.R
			r.Secao("HISTORICO DOS NAVEGADORES")
			r.Linha("Chrome (Default) de jogador: 41 paginas, 6 downloads, 9 pesquisas. Mais antiga: %s  Mais recente: %s", formataHora(time.Now().Add(-27*time.Hour)), formataHora(time.Now().Add(-2*time.Hour)))
			r.Add(Alerta, "Chrome (Default) de jogador so tem historico das ultimas 27h0m0s", "Historico limpo ha pouco tempo")
			r.Add(Critico, "Chrome (Default): acessos a site de cheat ('eulen.cc') (4)", formataHora(time.Now().Add(-26*time.Hour))+"  https://eulen.cc/login  [Eulen - Login]\n"+formataHora(time.Now().Add(-26*time.Hour))+"  https://eulen.cc/dashboard/download  [Eulen - Download]\n"+formataHora(time.Now().Add(-25*time.Hour))+"  https://eulen.cc/hwid-reset  [Eulen - HWID Reset]")
			r.Add(Critico, "Chrome (Default): pesquisas por 'fivem cheat' (3)", formataHora(time.Now().Add(-27*time.Hour))+"  pesquisou: fivem cheat gratis\n"+formataHora(time.Now().Add(-27*time.Hour))+"  pesquisou: melhor fivem cheat 2026\n"+formataHora(time.Now().Add(-26*time.Hour))+"  pesquisou: eulen fivem cheat")
			r.Add(Critico, "Chrome (Default): download de site de cheat ('eulen.cc')", formataHora(time.Now().Add(-26*time.Hour))+"  C:\\Users\\jogador\\Downloads\\loader_v2.rar  <- https://eulen.cc/dashboard/download")
			r.Add(Critico, "Chrome (Default): convite Discord com 'cheat'", formataHora(time.Now().Add(-26*time.Hour))+"  https://discord.gg/fivemcheat  [Discord]")
			r.Add(Alerta, "Chrome (Default): pesquisas com o termo 'pc check' (2)", formataHora(time.Now().Add(-5*time.Hour))+"  pesquisou: como passar pc check fivem\n"+formataHora(time.Now().Add(-5*time.Hour))+"  pesquisou: limpar rastro cheat fivem")
			r.Linha("Chrome (Default) de jogador (varredura profunda): cookie=1204  login=3  favorito=88  omnibox=140  topsite=20  favicon=910  aba=6  extensao=7")
			r.Add(Critico, "Chrome (Default): CONTA SALVA em site de cheat ('eulen.cc')", formataHora(time.Now().Add(-26*time.Hour))+"  https://eulen.cc/login  jogador_br\nConta salva significa que o jogador criou login no site, nao apenas visitou")
			r.Add(Critico, "Chrome (Default): cookie de 'eulen.cc' (3)", formataHora(time.Now().Add(-26*time.Hour))+"  .eulen.cc  session\n"+formataHora(time.Now().Add(-26*time.Hour))+"  .eulen.cc  cf_clearance\nCookie sobrevive a limpeza de historico. Se o cookie do site de cheat esta aqui, o site foi acessado e logado nesse navegador")
			r.Add(Critico, "Chrome (Default): endereco digitado 'eulen.cc'", formataHora(time.Now().Add(-27*time.Hour))+"  https://eulen.cc/  eulen")
			r.Add(Critico, "Chrome (Default): favorito 'ghost menu'", "  https://discord.gg/ghostmenu  Ghost Menu | Discord")
			r.Add(Alerta, "Chrome (Default): paginas com o termo 'spoofer' (2)", formataHora(time.Now().Add(-25*time.Hour))+"  https://www.youtube.com/watch?v=x1  [FiveM HWID Spoofer 2026 - UNDETECTED]\n"+formataHora(time.Now().Add(-25*time.Hour))+"  https://gitlab.com/explore/projects/topics/fivem-hwid-spoofer")
			r.Linha("Edge (Default) de jogador: 812 paginas, 14 downloads, 60 pesquisas. Mais antiga: %s  Mais recente: %s", formataHora(time.Now().Add(-35*24*time.Hour)), formataHora(time.Now().Add(-3*24*time.Hour)))
			r.Ok("Edge (Default) de jogador: nada de cheat no historico")
			pausaSimulada(320 * time.Millisecond)
		}, false},
		{"Discord", func(c *Contexto) {
			r := c.R
			r.Secao("DISCORD (cache, armazenamento local e anexos)")
			r.Linha("discord de jogador: 1842 arquivos (611 MB) analisados em C:\\Users\\jogador\\AppData\\Roaming\\discord")
			r.Add(Critico, "Anexo do Discord bate com 'eulen': eulen_loader_v3.exe", "https://cdn.discordapp.com/attachments/1140022/1180331/eulen_loader_v3.exe")
			r.Add(Critico, "Convite Discord de servidor de cheat ('fivemcheat'): fivemcheat", "https://discord.gg/fivemcheat")
			r.Add(Critico, "discord de jogador menciona 'eulen.cc' (2 ocorrencia(s))", formataHora(time.Now().Add(-26*time.Hour))+"  https://eulen.cc/dashboard\n    em: Cache\\Cache_Data\\f_0004a1\n"+formataHora(time.Now().Add(-26*time.Hour))+"  https://eulen.cc/hwid-reset\n    em: Cache\\Cache_Data\\f_0004a7")
			r.Add(Alerta, "discord de jogador menciona 'skript.gg' (1 ocorrencia(s))", formataHora(time.Now().Add(-30*time.Hour))+"  ...alguem tem a key do skript.gg pra me passar? o eulen ta detectado hj...\n    em: Local Storage\\leveldb\\000031.ldb")
			r.Add(Alerta, "discord de jogador menciona 'hwid spoofer' (1 ocorrencia(s))", formataHora(time.Now().Add(-25*time.Hour))+"  ...comprei o hwid spoofer permanente, agora da pra entrar na cidade de novo...\n    em: Local Storage\\leveldb\\000031.ldb")
			r.Add(Info, "Anexos executaveis/compactados vistos no discord de jogador: 3", "loader_v2.rar  https://cdn.discordapp.com/attachments/1140022/1180200/loader_v2.rar\nspoofer.zip  https://cdn.discordapp.com/attachments/1140022/1181004/spoofer.zip\nsetup_discord_bot.exe  https://cdn.discordapp.com/attachments/9900/9911/setup_discord_bot.exe")
			r.Add(Info, "Convites Discord vistos no cache de jogador: 6", "cidadealta, filadelfiarp, fivemcheat, eulen-support, shasupport, ripzone")
			pausaSimulada(340 * time.Millisecond)
		}, false},
		{"Varredura de arquivos", func(c *Contexto) {
			r := c.R
			r.Secao("VARREDURA DE ARQUIVOS")
			r.Linha("148213 arquivos analisados em 1m12s")
			r.Add(Critico, "Arquivo bate com assinatura 'kdmapper': kdmapper.exe", "C:\\Users\\jogador\\Downloads\\kdmapper.exe\nmodificado: "+formataHora(time.Now().Add(-31*time.Hour))+"  tamanho: 412 KB")
			r.Add(Critico, "Executavel DISFARCADO com outra extensao: config.dat", "C:\\Users\\jogador\\AppData\\Roaming\\hk\\config.dat\nO arquivo comeca com cabecalho MZ (programa Windows) mas nao tem extensao .exe/.dll")
			r.Add(Alerta, "Arquivo bate com assinatura 'cheat engine': Cheat Engine 7.5", "C:\\Program Files\\Cheat Engine 7.5")
			r.Add(Alerta, "Executavel com nome aleatorio: a9f31c7d4b.exe", "C:\\Users\\jogador\\AppData\\Local\\Temp\\a9f31c7d4b.exe")
			r.Add(Info, "Executaveis novos/modificados nos ultimos 7 dias em pastas do usuario: 12", formataHora(time.Now().Add(-24*time.Hour))+"      412 KB  C:\\Users\\jogador\\Downloads\\kdmapper.exe")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		{"Strings de cheat no conteudo dos arquivos", func(c *Contexto) {
			r := c.R
			r.Secao("STRINGS DE CHEAT NO CONTEUDO DOS ARQUIVOS")
			for i, pasta := range []string{"C:\\Users\\jogador\\Downloads", "C:\\Users\\jogador\\Documents\\scripts", "C:\\Users\\jogador\\AppData\\Local\\Temp", "C:\\Users\\jogador\\AppData\\Roaming\\hk"} {
				r.Progresso("%d arquivos lidos (%d MB) em %ds. Agora em: %s", (i+1)*15300, (i+1)*978, (i+1)*31, pasta)
				pausaSimulada(700 * time.Millisecond)
			}
			r.Linha("61204 arquivos (3912 MB) lidos em 2m05s")
			r.Add(Critico, "Executavel/script contem string 'eulen' (+2: eulen.cc, lua executor): svchost_update.exe", formataHora(time.Now().Add(-28*time.Hour))+"  4812 KB  C:\\Users\\jogador\\AppData\\Roaming\\hk\\svchost_update.exe\n...Eulen Lua Executor - connecting to api.eulen.cc...")
			r.Add(Critico, "Executavel/script contem string 'redengine': dump_inventory.lua", formataHora(time.Now().Add(-29*time.Hour))+"  6 KB  C:\\Users\\jogador\\Documents\\scripts\\dump_inventory.lua\n...-- dumped with redENGINE resource dumper -- TriggerServerEvent('inventory:giveItem'...")
			r.Add(Alerta, "Arquivo contem string 'hwid spoofer': notas.txt", formataHora(time.Now().Add(-24*time.Hour))+"  1 KB  C:\\Users\\jogador\\Desktop\\notas.txt\n...key do hwid spoofer: XXXX-YYYY, key do eulen no discord...")
			pausaSimulada(300 * time.Millisecond)
		}, false},
	}
}

func etapasSimuladasLimpo() []Etapa {
	return []Etapa{
		{"Sistema e integridade de codigo", func(c *Contexto) {
			r := c.R
			cabecalhoSimulado(c, false)
			r.Ok("Integridade de codigo normal (drivers precisam de assinatura)")
			r.Ok("Secure Boot ligado")
			r.Ok("HVCI (integridade de memoria) ligado")
			r.Ok("Prefetch habilitado (EnablePrefetcher=3)")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		{"Servicos de rastreio e protecao", func(c *Contexto) {
			r := c.R
			r.Secao("SERVICOS DO WINDOWS (rastreio e protecao)")
			for _, s := range []string{"EventLog", "SysMain", "PcaSvc", "DPS", "Dnscache", "WinDefend", "Schedule"} {
				r.Linha("%-24s %-10s inicio: %-11s %s", s, "rodando", "automatico", "servico de rastreio ativo")
			}
			r.Ok("Todos os servicos de rastreio e protecao estao ativos")
			pausaSimulada(280 * time.Millisecond)
		}, false},
		{"Windows Defender", func(c *Contexto) {
			r := c.R
			r.Secao("WINDOWS DEFENDER")
			r.Ok("Nenhuma exclusao configurada no Defender (via registro)")
			r.Ok("Defender ativo com protecao em tempo real")
			r.Linha("Assinaturas atualizadas: %s   Ultimo scan rapido: %s", formataHora(time.Now().Add(-5*time.Hour)), formataHora(time.Now().Add(-20*time.Hour)))
			pausaSimulada(280 * time.Millisecond)
		}, false},
		{"Logs de eventos", func(c *Contexto) {
			r := c.R
			r.Secao("LOGS DE EVENTOS DO WINDOWS")
			r.Ok("Nenhum registro de limpeza do log Security (evento 1102)")
			r.Ok("Nenhum registro de limpeza de logs do sistema (evento 104)")
			r.Linha("%-58s registros: %-7d mais antigo: %s  limite: %d MB", "Security", 18422, formataHora(time.Now().Add(-44*24*time.Hour)), 20)
			r.Linha("%-58s registros: %-7d mais antigo: %s  limite: %d MB", "System", 9137, formataHora(time.Now().Add(-45*24*time.Hour)), 20)
			r.Add(Info, "4 servico(s)/driver(s) instalado(s) nos ultimos 30 dias", formataHora(time.Now().Add(-9*24*time.Hour))+"  NVDisplay.ContainerLocalSystem  [win32 own process]  C:\\Program Files\\NVIDIA Corporation\\Display.NvContainer\\NVDisplay.Container.exe")
			pausaSimulada(320 * time.Millisecond)
		}, false},
		{"Historico de execucao no registro", func(c *Contexto) {
			r := c.R
			r.Secao("HISTORICO DE EXECUCAO (registro do Windows)")
			r.Linha("Entradas encontradas: BAM=87  UserAssist=214  PcaSvc Store=132  MuiCache=190  RecentDocs=64")
			r.Add(Info, "Ultimos executaveis registrados no BAM (7 dias): 23", formataHora(time.Now().Add(-4*time.Hour))+"  \\Device\\HarddiskVolume3\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.exe")
			r.Ok("Nenhum comando de ocultacao no historico do PowerShell")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		{"Prefetch", func(c *Contexto) {
			r := c.R
			r.Secao("PREFETCH (programas executados)")
			r.Linha("428 arquivos .pf em C:\\Windows\\Prefetch")
			r.Linha("Mais antigo: %s   Mais recente: %s", formataHora(time.Now().Add(-44*24*time.Hour)), formataHora(time.Now().Add(-12*time.Minute)))
			r.Add(Info, "Programas executados nas ultimas 48h (Prefetch): 37", formataHora(time.Now().Add(-3*time.Hour))+"  FIVEM.EXE")
			pausaSimulada(240 * time.Millisecond)
		}, false},
		{"Arquivos recentes e lixeira", func(c *Contexto) {
			r := c.R
			r.Secao("ARQUIVOS RECENTES E LIXEIRA")
			r.Linha("Recentes de jogador: 142 atalhos, ultimo em %s", formataHora(time.Now().Add(-2*time.Hour)))
			r.Linha("Lixeira de jogador em C:\\: 8 itens")
			pausaSimulada(220 * time.Millisecond)
		}, false},
		{"Processos, handles, overlay e drivers", func(c *Contexto) {
			r := c.R
			r.Secao("PROCESSOS EM EXECUCAO (analise ponto a ponto)")
			r.Linha("171 processos em execucao")
			processosSimulados(c, false)
			r.Secao("DRIVERS DE KERNEL CARREGADOS")
			r.Linha("165 drivers carregados")
			r.Ok("Nenhum driver vulneravel ou fora de lugar carregado. Drivers mapeados manualmente (kdmapper) nao aparecem nesta lista")
			pausaSimulada(320 * time.Millisecond)
		}, false},
		etapaSimuladaSimples("Integridade do jogo (FiveM e GTA V)", "INTEGRIDADE DO JOGO (FiveM e GTA V)", func(c *Contexto) {
			c.R.Ok("Windows rodando direto no hardware, nao em maquina virtual")
			c.R.Linha("FiveM de jogador em C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app")
			c.R.Linha("198 arquivos do FiveM conferidos em 38s")
			c.R.Ok("Arquivos do FiveM com assinatura digital do fabricante, nenhum trocado")
			c.R.Ok("Nenhum plugin .asi nem dll de carregamento de mod na pasta do GTA V")
		}),
		etapaSimuladaSimples("Conteudo dos pacotes baixados", "CONTEUDO DOS PACOTES BAIXADOS (zip, rar, 7z)", func(c *Contexto) {
			c.R.Linha("2 pacote(s) compactado(s) para abrir e conferir por dentro")
			c.R.Ok("Nenhum programa, dll ou script escondido dentro dos pacotes conferidos")
		}),
		etapaSimuladaSimples("Hardware (DMA, KMBox, aim assist)", "HARDWARE (placa DMA, KMBox, dispositivos de aim assist)", func(c *Contexto) {
			c.R.Linha("176 dispositivos PCI/USB/HID conhecidos pelo Windows (conectados agora ou no passado)")
			c.R.Ok("Nenhuma placa DMA/FPGA nem dispositivo de aim assist (KMBox, MAKCU, Xim, Cronus, Arduino) no historico de hardware")
		}),
		{"FiveM", func(c *Contexto) {
			r := c.R
			r.Secao("FIVEM")
			r.Linha("Instalacao de jogador: C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app")
			r.Linha("Ultimo log: CitizenFX_log_2026-09-09T120411.log (842 KB)")
			r.Ok("Nenhum plugin .asi/.dll fora do padrao no FiveM.app")
			pausaSimulada(220 * time.Millisecond)
		}, false},
		{"Cache DNS e journal USN", func(c *Contexto) {
			r := c.R
			r.Secao("CACHE DNS (sites acessados desde o boot)")
			r.Linha("74 nomes unicos no cache DNS")
			r.Ok("Nenhum dominio de cheat no cache DNS")
			r.Secao("JOURNAL USN (historico de alteracoes do disco)")
			r.Linha("C:: journal criado em %s", formataHora(time.Now().Add(-45*24*time.Hour)))
			r.Ok("Journal USN intacto desde a instalacao do Windows")
			pausaSimulada(240 * time.Millisecond)
		}, false},
		{"Historico dos navegadores", func(c *Contexto) {
			r := c.R
			r.Secao("HISTORICO DOS NAVEGADORES")
			r.Linha("Chrome (Default) de jogador: 3120 paginas, 48 downloads, 210 pesquisas. Mais antiga: %s  Mais recente: %s", formataHora(time.Now().Add(-44*24*time.Hour)), formataHora(time.Now().Add(-1*time.Hour)))
			r.Ok("Chrome (Default) de jogador: nada de cheat no historico")
			r.Add(Info, "Downloads de executaveis/compactados nos ultimos 30 dias: 2", formataHora(time.Now().Add(-2*24*time.Hour))+"  C:\\Users\\jogador\\Downloads\\GeForce_Experience_setup.exe  <- https://www.nvidia.com/pt-br/geforce/geforce-experience/\n"+formataHora(time.Now().Add(-9*24*time.Hour))+"  C:\\Users\\jogador\\Downloads\\DiscordSetup.exe  <- https://discord.com/download")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		{"Discord", func(c *Contexto) {
			r := c.R
			r.Secao("DISCORD (cache, armazenamento local e anexos)")
			r.Linha("discord de jogador: 2210 arquivos (740 MB) analisados em C:\\Users\\jogador\\AppData\\Roaming\\discord")
			r.Ok("discord de jogador: nenhuma mencao a cheat no cache")
			r.Add(Info, "Convites Discord vistos no cache de jogador: 4", "cidadealta, filadelfiarp, nvidia, valorant")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		{"Varredura de arquivos", func(c *Contexto) {
			r := c.R
			r.Secao("VARREDURA DE ARQUIVOS")
			r.Linha("212904 arquivos analisados em 1m48s")
			r.Ok("Nenhum arquivo bateu com as assinaturas de cheat, injecao ou limpeza")
			r.Add(Info, "Executaveis novos/modificados nos ultimos 7 dias em pastas do usuario: 6", formataHora(time.Now().Add(-2*24*time.Hour))+"    62310 KB  C:\\Users\\jogador\\Downloads\\GeForce_Experience_setup.exe")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		{"Strings de cheat no conteudo dos arquivos", func(c *Contexto) {
			r := c.R
			r.Secao("STRINGS DE CHEAT NO CONTEUDO DOS ARQUIVOS")
			for i, pasta := range []string{"C:\\Users\\jogador\\Downloads", "C:\\Users\\jogador\\Documents", "C:\\Users\\jogador\\AppData\\Local"} {
				r.Progresso("%d arquivos lidos (%d MB) em %ds. Agora em: %s", (i+1)*28000, (i+1)*1736, (i+1)*53, pasta)
				pausaSimulada(700 * time.Millisecond)
			}
			r.Linha("84110 arquivos (5210 MB) lidos em 2m40s")
			r.Ok("Nenhum arquivo com string de cheat no conteudo")
			pausaSimulada(300 * time.Millisecond)
		}, false},
	}
}

func etapaSimuladaSimples(nome, secao string, fn func(c *Contexto)) Etapa {
	return Etapa{nome, func(c *Contexto) {
		c.R.Secao(secao)
		fn(c)
		pausaSimulada(280 * time.Millisecond)
	}, false}
}

func etapasSimuladasAtivo() []Etapa {
	return []Etapa{
		{"Sistema e integridade de codigo", func(c *Contexto) {
			r := c.R
			cabecalhoSimulado(c, false)
			r.Ok("Integridade de codigo normal (drivers precisam de assinatura)")
			r.Ok("Secure Boot ligado")
			r.Add(Info, "HVCI (integridade de memoria) desligado", "Comum em PC gamer, mas cheats de kernel exigem isso desligado")
			r.Ok("Prefetch habilitado (EnablePrefetcher=3)")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		etapaSimuladaSimples("Origem do Windows (original ou modificado)", "ORIGEM DO WINDOWS (instalacao original ou modificada)", func(c *Contexto) {
			c.R.Linha("Edicao: Windows 11 Pro  build 26100")
			c.R.Ok("Windows com cara de instalacao original: servicos, arquivos e componentes de fabrica no lugar")
		}),
		etapaSimuladaSimples("Servicos de rastreio e protecao", "SERVICOS DO WINDOWS (rastreio e protecao)", func(c *Contexto) {
			c.R.Ok("Todos os servicos de rastreio e protecao estao ativos")
		}),
		etapaSimuladaSimples("Windows Defender", "WINDOWS DEFENDER", func(c *Contexto) {
			c.R.Add(Critico, "Exclusao no Defender: C:\\Users\\jogador\\AppData\\Local\\Temp", "Exclusao em pasta de download/temp/area de trabalho, padrao de loader de cheat. Exclusao de paths no Defender. Loaders de cheat pedem para excluir a pasta antes de rodar")
			c.R.Ok("Defender ativo com protecao em tempo real")
		}),
		etapaSimuladaSimples("Logs de eventos", "LOGS DE EVENTOS DO WINDOWS", func(c *Contexto) {
			c.R.Ok("Nenhum registro de limpeza do log Security (evento 1102)")
			c.R.Ok("Nenhum registro de limpeza de logs do sistema (evento 104)")
		}),
		etapaSimuladaSimples("ETW / kernel", "ETW / KERNEL (rastreamento do proprio Windows)", func(c *Contexto) {
			c.R.Linha("171 sessoes de rastreamento ETW ativas no sistema")
			c.R.Ok("Sessoes ETW essenciais do Windows estao rodando (o sistema ainda registra eventos)")
			c.R.Ok("Code Integrity nao registrou driver ou binario nao assinado bloqueado nos ultimos 90 dias")
			c.R.Linha("Captura do kernel: 5210 eventos em 21s (4402 carregamentos de imagem, 70 processos novos, 102 consultas DNS)")
			c.R.Ok("Teste ativo do ETW passou: o kernel registrou os 10 processos que o scanner iniciou de proposito")
			c.R.Add(Critico, "Consulta DNS a dominio de cheat ('eulen.gg') durante a checagem: auth.eulen.gg", "Capturada ao vivo pelo ETW. Loader de cheat consulta o servidor de licenca de tempos em tempos, entao isso indica cheat ativo agora")
		}),
		etapaSimuladaSimples("Historico de execucao no registro", "HISTORICO DE EXECUCAO (registro do Windows)", func(c *Contexto) {
			c.R.Linha("Entradas encontradas: BAM=91  UserAssist=210  PcaSvc Store=140  MuiCache=201  RecentDocs=70")
			c.R.Add(Critico, "Executado (BAM) bate com assinatura 'eulen': eulen_loader.exe", formataHora(time.Now().Add(-40*time.Minute))+"  usuario: jogador\nC:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe")
		}),
		etapaSimuladaSimples("Prefetch", "PREFETCH (programas executados)", func(c *Contexto) {
			c.R.Linha("402 arquivos .pf em C:\\Windows\\Prefetch")
			c.R.Add(Critico, "Prefetch de programa que bate com assinatura 'eulen': EULEN_LOADER.EXE", "Ultima execucao: "+formataHora(time.Now().Add(-40*time.Minute))+"  (EULEN_LOADER.EXE-7A11C0F2.pf)")
		}),
		etapaSimuladaSimples("Artefatos do Windows (ShimCache, crashes, atalhos)", "ARTEFATOS DO WINDOWS (ShimCache, crashes, atalhos)", func(c *Contexto) {
			c.R.Linha("AppCompatCache (ShimCache): 744 executaveis registrados pelo Windows")
			c.R.Add(Critico, "ShimCache registrou execucao de arquivo com assinatura 'eulen': eulen_loader.exe", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe\nmodificado: "+formataHora(time.Now().Add(-45*time.Minute))+"\nO ShimCache guarda o caminho mesmo que o arquivo tenha sido apagado e o Prefetch limpo")
			c.R.Ok("Nenhum relatorio de erro de programa com nome de cheat")
		}),
		etapaSimuladaSimples("Arquivos recentes e lixeira", "ARQUIVOS RECENTES E LIXEIRA", func(c *Contexto) {
			c.R.Linha("Recentes de jogador: 131 atalhos, ultimo em %s", formataHora(time.Now().Add(-30*time.Minute)))
			c.R.Add(Critico, "Arquivo recente de jogador bate com assinatura 'eulen'", "C:\\Users\\jogador\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\eulen_loader.lnk")
		}),
		{"Processos, handles, overlay e drivers", func(c *Contexto) {
			r := c.R
			r.Secao("PROCESSOS EM EXECUCAO (analise ponto a ponto)")
			r.Linha("187 processos em execucao")
			r.Progresso("Lendo versao, assinatura e hora de criacao de 187 processos")
			pausaSimulada(500 * time.Millisecond)
			processosSimulados(c, true)
			r.Add(Critico, "Processo se passando por processo do Windows: svchost.exe (PID 8210)", "C:\\Users\\jogador\\AppData\\Roaming\\svchost.exe\nO svchost.exe legitimo fica em C:\\windows\\system32. Rodar de outra pasta e ocultacao classica")
			r.Processo(8210, "svchost.exe", "C:\\Users\\jogador\\AppData\\Roaming\\svchost.exe", "cheat", "explorer.exe")
			r.Add(Critico, "Executavel APAGADO enquanto ainda roda: a9f31c7d4b.exe (PID 8140)", "C:\\Users\\jogador\\AppData\\Local\\Temp\\a9f31c7d4b.exe\nO arquivo nao existe mais no disco mas o processo continua. Loader de cheat se apaga depois de injetar para nao deixar rastro")
			r.Add(Critico, "Ferramenta 'cheat engine' RENOMEADA para notepad2.exe (PID 8300)", "C:\\Users\\jogador\\Desktop\\notepad2.exe\nNome original no executavel: cheatengine-x86_64.exe  Produto: Cheat Engine\nRenomear o exe e a forma mais comum de esconder cheat/injetor de quem olha a lista de processos")
			r.Processo(8300, "notepad2.exe", "C:\\Users\\jogador\\Desktop\\notepad2.exe", "cheat", "explorer.exe")
			r.Add(Alerta, "Executavel SEM assinatura digital rodando de pasta de usuario: eulen_loader.exe (PID 8102)", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe\nPrograma serio costuma ser assinado. Sem assinatura em Temp/Downloads/Desktop/Roaming e tipico de loader")
			r.Add(Info, "Processos iniciados nos 15 minutos antes da checagem: 3", formataHora(time.Now().Add(-9*time.Minute))+"  eulen_loader.exe  C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe\n"+formataHora(time.Now().Add(-8*time.Minute))+"  notepad2.exe  C:\\Users\\jogador\\Desktop\\notepad2.exe\n"+formataHora(time.Now().Add(-2*time.Minute))+"  chrome.exe  C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
			r.Ok("Lista de processos consistente entre Toolhelp, EnumProcesses e NtQuerySystemInformation (nada escondido)")
			r.Progresso("Procurando processos com handle aberto no FiveM (PID 6210)")
			pausaSimulada(500 * time.Millisecond)
			r.Linha("5 handle(s) de outros processos apontando para o FiveM")
			r.Add(Critico, "Processo com acesso de ESCRITA na memoria do FiveM: ext.exe (PID 8410)", "C:\\Users\\jogador\\AppData\\Roaming\\hk\\ext.exe\nAcesso: VM_READ|VM_WRITE|VM_OPERATION (0x38)\nE assim que cheat externo injeta e altera o jogo. Overlay e gravador so precisam de leitura, e mesmo assim sao de fabricante conhecido")
			r.Processo(8410, "ext.exe", "C:\\Users\\jogador\\AppData\\Roaming\\hk\\ext.exe", "cheat", "svchost.exe")
			r.Add(Info, "Processos com handle no FiveM: 5", "ext.exe (PID 8410)  VM_READ|VM_WRITE|VM_OPERATION (0x38)  C:\\Users\\jogador\\AppData\\Roaming\\hk\\ext.exe\nobs64.exe (PID 5120)  VM_READ (0x410)  C:\\Program Files\\obs-studio\\bin\\64bit\\obs64.exe\nDiscord.exe (PID 2210)  ALL_ACCESS  C:\\Users\\jogador\\AppData\\Local\\Discord\\app-1.0.9200\\Discord.exe\nsvchost.exe (PID 812)  ALL_ACCESS  C:\\Windows\\System32\\svchost.exe\ncsrss.exe (PID 620)  ALL_ACCESS  C:\\Windows\\System32\\csrss.exe")
			r.Add(Critico, "Janela OVERLAY transparente cobrindo a tela inteira: ext.exe (PID 8410)", "Titulo: \"\"  Classe: ImGui Overlay  1920x1080\nC:\\Users\\jogador\\AppData\\Roaming\\hk\\ext.exe\nJanela invisivel ao clique, sempre no topo e do tamanho da tela e exatamente como ESP externo desenha por cima do jogo")
			r.Secao("DRIVERS DE KERNEL CARREGADOS")
			r.Linha("171 drivers carregados")
			r.Ok("Nenhum driver vulneravel ou fora de lugar carregado. Drivers mapeados manualmente (kdmapper) nao aparecem nesta lista")
			pausaSimulada(340 * time.Millisecond)
		}, false},
		etapaSimuladaSimples("Hardware (DMA, KMBox, aim assist)", "HARDWARE (placa DMA, KMBox, dispositivos de aim assist)", func(c *Contexto) {
			c.R.Linha("214 dispositivos PCI/USB/HID conhecidos pelo Windows (conectados agora ou no passado)")
			c.R.Add(Alerta, "Dispositivo de aim assist/macro ('kmbox'): KMBOX NET", "HID\\VID_1A86&PID_E026\\7&2\nja foi conectado (nao esta agora)\nKMBox, MAKCU, Xim, Cronus e Arduino Leonardo emulam mouse para aimbot por hardware")
		}),
		etapaSimuladaSimples("FiveM", "FIVEM", func(c *Contexto) {
			c.R.Linha("Instalacao de jogador: C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app")
			c.R.Add(Critico, "Log do FiveM menciona assinatura de cheat", "[eulen] [   482375] Loading module: eulen.dll")
		}),
		etapaSimuladaSimples("Cache DNS e journal USN", "CACHE DNS (sites acessados desde o boot)", func(c *Contexto) {
			c.R.Linha("88 nomes unicos no cache DNS")
			c.R.Add(Critico, "Cache DNS tem dominio de cheat ('eulen.gg'): auth.eulen.gg", "O PC resolveu esse dominio desde o ultimo boot")
		}),
		etapaSimuladaSimples("Historico dos navegadores", "HISTORICO DOS NAVEGADORES", func(c *Contexto) {
			c.R.Linha("Chrome (Default) de jogador: 2890 paginas, 51 downloads, 190 pesquisas. Mais antiga: %s  Mais recente: %s", formataHora(time.Now().Add(-44*24*time.Hour)), formataHora(time.Now().Add(-1*time.Hour)))
			c.R.Add(Critico, "Chrome (Default): acessos a site de cheat ('eulen.gg') (2)", formataHora(time.Now().Add(-2*time.Hour))+"  https://eulen.gg/dashboard  [Eulen - Dashboard]\n"+formataHora(time.Now().Add(-3*24*time.Hour))+"  https://eulen.gg/  [Eulen.gg - FiveM Spoofer, Aimbot, Lua Executor]")
		}),
		etapaSimuladaSimples("Discord", "DISCORD (cache, armazenamento local e anexos)", func(c *Contexto) {
			c.R.Linha("discord de jogador: 2044 arquivos (590 MB) analisados em C:\\Users\\jogador\\AppData\\Roaming\\discord")
			c.R.Add(Critico, "Convite Discord de servidor de cheat ('ghost menu'): ghostmenu", "https://discord.gg/ghostmenu")
			c.R.Add(Alerta, "discord de jogador menciona 'puxando arma' (1 ocorrencia(s))", formataHora(time.Now().Add(-5*time.Hour))+"  ...mano o ghost ta puxando arma de novo, atualizou hj...\n    em: Local Storage\\leveldb\\000031.ldb")
		}),
		{"Varredura de arquivos", func(c *Contexto) {
			c.R.Secao("VARREDURA DE ARQUIVOS")
			c.R.Linha("151022 arquivos analisados em 1m10s")
			c.R.Add(Critico, "Arquivo bate com assinatura 'eulen': eulen_loader.exe", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe\nmodificado: "+formataHora(time.Now().Add(-41*time.Minute))+"  tamanho: 3120 KB")
			pausaSimulada(300 * time.Millisecond)
		}, true},
		{"Strings de cheat no conteudo dos arquivos", func(c *Contexto) {
			c.R.Secao("STRINGS DE CHEAT NO CONTEUDO DOS ARQUIVOS")
			for i, pasta := range []string{"C:\\Users\\jogador\\Downloads", "C:\\Users\\jogador\\AppData\\Local\\Temp"} {
				c.R.Progresso("%d arquivos lidos (%d MB) em %ds. Agora em: %s", (i+1)*20100, (i+1)*1400, (i+1)*44, pasta)
				pausaSimulada(600 * time.Millisecond)
			}
			c.R.Linha("58900 arquivos (4100 MB) lidos em 1m58s")
			c.R.Add(Critico, "Executavel/script contem string 'eulen' (+1: eulen.gg): eulen_loader.exe", formataHora(time.Now().Add(-41*time.Minute))+"  3120 KB  C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe\n...Eulen Loader - auth.eulen.gg - session...")
			pausaSimulada(300 * time.Millisecond)
		}, true},
	}
}

func etapasSimuladasRastros() []Etapa {
	return []Etapa{
		{"Sistema e integridade de codigo", func(c *Contexto) {
			r := c.R
			cabecalhoSimulado(c, false)
			r.Ok("Integridade de codigo normal (drivers precisam de assinatura)")
			r.Ok("Secure Boot ligado")
			r.Add(Info, "PC reiniciado ha menos de 30 minutos", "Reiniciar antes da checagem limpa processos, modulos injetados e o cache DNS")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		etapaSimuladaSimples("Origem do Windows (original ou modificado)", "ORIGEM DO WINDOWS (instalacao original ou modificada)", func(c *Contexto) {
			c.R.Linha("Edicao: Windows 10 Pro  build 26200")
			c.R.Linha("Servicos de fabrica ausentes: 3   Arquivos de fabrica ausentes: 3   Marcas de ISO modificada: 1")
			c.R.Add(Critico, "O Windows Defender foi REMOVIDO deste Windows", "O servico WinDefend nao existe no sistema. Desligar o Defender e uma coisa, arrancar ele da instalacao e outra: isso so acontece em Windows modificado (ISO 'lite', 'gamer', Ghost Spectre e parecidas) ou em quem usou ferramenta de remocao.\nSem Defender nao existe historico de ameaca, nao existe quarentena e nao existe deteccao")
			c.R.Add(Critico, "Este Windows NAO E ORIGINAL: foi modificado antes de ser instalado", "Edicao informada: Windows 10 Pro  build 26200\n3 servico(s) de fabrica nao existem: SecurityHealthService, Sense, WinDefend\n3 arquivo(s) do proprio Windows foram removidos: MsMpEng.exe, SecurityHealthService.exe, smartscreen.exe\nmarcas encontradas no sistema: Ghost Spectre em BuildLab\nUm Windows modificado remove servicos, logs e protecoes de fabrica")
		}),
		etapaSimuladaSimples("Servicos de rastreio e protecao", "SERVICOS DO WINDOWS (rastreio e protecao)", func(c *Contexto) {
			c.R.Add(Alerta, "Servico SysMain esta DESATIVADO", "Superfetch/Prefetch. Desligar apaga o registro de programas executados")
			c.R.Add(Critico, "Servico PcaSvc esta DESATIVADO", "Assistente de compatibilidade. Grava caminho de cada exe executado")
			c.R.Add(Alerta, "Servico Dnscache esta PARADO", "Cache de DNS. Desligar limpa o historico de sites do loader do cheat")
		}),
		etapaSimuladaSimples("Windows Defender", "WINDOWS DEFENDER", func(c *Contexto) {
			c.R.Ok("Nenhuma exclusao configurada no Defender (via registro)")
			c.R.Ok("Defender ativo com protecao em tempo real")
		}),
		etapaSimuladaSimples("Logs de eventos", "LOGS DE EVENTOS DO WINDOWS", func(c *Contexto) {
			c.R.Add(Critico, "Log de SEGURANCA foi LIMPO em "+formataHora(time.Now().Add(-50*time.Minute)), "Evento 1102, usuario: jogador. O evento 1102 sobrevive a limpeza justamente para marcar quem limpou")
			c.R.Add(Critico, "Log 'System' foi LIMPO em "+formataHora(time.Now().Add(-50*time.Minute)), "Evento 104, usuario: jogador")
			c.R.Add(Critico, "Log 'Application' foi LIMPO em "+formataHora(time.Now().Add(-50*time.Minute)), "Evento 104, usuario: jogador")
			c.R.Add(Critico, "Log 'Microsoft-Windows-PowerShell/Operational' foi LIMPO em "+formataHora(time.Now().Add(-49*time.Minute)), "Evento 104, usuario: jogador")
			c.R.Add(Critico, "1 script(s) PowerShell de ocultacao/cheat registrados", formataHora(time.Now().Add(-49*time.Minute))+"  [apaga o journal USN]  fsutil usn deletejournal /d C:")
		}),
		etapaSimuladaSimples("ETW / kernel", "ETW / KERNEL (rastreamento do proprio Windows)", func(c *Contexto) {
			c.R.Linha("158 sessoes de rastreamento ETW ativas no sistema")
			c.R.Add(Critico, "2 sessao(oes) ETW essencial(is) do Windows PARADA(S)", "eventlog-security (canal ETW que alimenta o log de Seguranca)\neventlog-system (canal ETW que alimenta o log de Sistema)\nParar essas sessoes faz o Windows deixar de gravar eventos sem que o log pareca limpo. Tecnica de ocultacao mais fina que apagar o log")
			c.R.Add(Alerta, "Sessao ETW de seguranca foi mexida: DefenderApiLogger", formataHora(time.Now().Add(-47*time.Minute))+"  evento 3  DefenderApiLogger\nParar a sessao de rastreamento do antivirus ou do anticheat e forma de cegar a protecao sem desinstalar nada")
			c.R.Linha("Captura do kernel: 3980 eventos em 21s (3310 carregamentos de imagem, 52 processos novos, 41 consultas DNS)")
			c.R.Ok("Teste ativo do ETW passou: o kernel registrou os 10 processos que o scanner iniciou de proposito")
		}),
		etapaSimuladaSimples("Historico de execucao no registro", "HISTORICO DE EXECUCAO (registro do Windows)", func(c *Contexto) {
			c.R.Linha("Entradas encontradas: BAM=3  UserAssist=0  PcaSvc Store=0  MuiCache=44  RecentDocs=0")
			c.R.Add(Alerta, "BAM com poucas entradas (3)", "Pode ter sido limpo recentemente")
			c.R.Add(Alerta, "UserAssist vazio", "Historico de programas abertos pelo Explorer foi limpo ou desativado")
			c.R.Add(Alerta, "Compatibility Assistant Store vazio", "Historico do PcaSvc limpo (ou servico parado ha muito tempo)")
			c.R.Add(Alerta, "Abriu a pasta Prefetch pela caixa Executar (jogador)", "prefetch\nQuem abre essa pasta normalmente e para apagar os .pf. Cruzar com a checagem de Prefetch")
			c.R.Add(Critico, "Historico PowerShell de jogador tem 3 comando(s) de ocultacao/cheat", "[limpa log de eventos] wevtutil cl Security\n[apaga o journal USN] fsutil usn deletejournal /d C:\n[apaga o Prefetch] Remove-Item C:\\Windows\\Prefetch\\* -Force")
		}),
		etapaSimuladaSimples("Prefetch", "PREFETCH (programas executados)", func(c *Contexto) {
			c.R.Linha("6 arquivos .pf em C:\\Windows\\Prefetch")
			c.R.Add(Critico, "Prefetch foi LIMPO nas ultimas 24h", "Todos os 6 arquivos .pf sao posteriores a "+formataHora(time.Now().Add(-48*time.Minute))+", mas o Windows foi instalado em "+formataHora(c.Instalacao))
		}),
		etapaSimuladaSimples("Artefatos do Windows (ShimCache, crashes, atalhos)", "ARTEFATOS DO WINDOWS (ShimCache, crashes, atalhos)", func(c *Contexto) {
			c.R.Linha("AppCompatCache (ShimCache): 12 executaveis registrados pelo Windows")
			c.R.Add(Alerta, "ShimCache com pouquissimas entradas (12)", "O AppCompatCache guarda executaveis vistos pelo Windows e so e reescrito no desligamento. Quase vazio indica limpeza direta no registro")
			c.R.Linha("Atalhos e jump lists analisados: 3")
			c.R.Ok("Nenhum atalho ou jump list apontando para cheat")
		}),
		etapaSimuladaSimples("Arquivos recentes e lixeira", "ARQUIVOS RECENTES E LIXEIRA", func(c *Contexto) {
			c.R.Add(Alerta, "Pasta de recentes de jogador esta vazia", "Limpeza manual ou por ferramenta (CCleaner e similares)")
			c.R.Linha("Lixeira de jogador em C:\\: 0 itens")
		}),
		{"Processos, handles, overlay e drivers", func(c *Contexto) {
			r := c.R
			r.Secao("PROCESSOS EM EXECUCAO (analise ponto a ponto)")
			r.Linha("162 processos em execucao")
			processosSimulados(c, false)
			r.Secao("DRIVERS DE KERNEL CARREGADOS")
			r.Ok("Nenhum driver vulneravel ou fora de lugar carregado. Drivers mapeados manualmente (kdmapper) nao aparecem nesta lista")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		etapaSimuladaSimples("Hardware (DMA, KMBox, aim assist)", "HARDWARE (placa DMA, KMBox, dispositivos de aim assist)", func(c *Contexto) {
			c.R.Linha("198 dispositivos PCI/USB/HID conhecidos pelo Windows (conectados agora ou no passado)")
			c.R.Ok("Nenhuma placa DMA/FPGA nem dispositivo de aim assist (KMBox, MAKCU, Xim, Cronus, Arduino) no historico de hardware")
		}),
		etapaSimuladaSimples("FiveM", "FIVEM", func(c *Contexto) {
			c.R.Linha("Instalacao de jogador: C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app")
			c.R.Add(Alerta, "Pasta de logs do FiveM vazia", "Os logs CitizenFX_log_*.log foram apagados")
		}),
		etapaSimuladaSimples("Cache DNS e journal USN", "CACHE DNS (sites acessados desde o boot)", func(c *Contexto) {
			c.R.Linha("2 nomes unicos no cache DNS")
			c.R.Add(Alerta, "Cache DNS praticamente vazio com o PC ligado ha mais de 30 min", "ipconfig /flushdns ou servico Dnscache parado")
			c.R.Secao("JOURNAL USN (historico de alteracoes do disco)")
			c.R.Add(Alerta, "Journal USN de C: foi recriado em "+formataHora(time.Now().Add(-49*time.Minute)), "Windows instalado em "+formataHora(c.Instalacao)+". Journal recriado depois da instalacao indica 'fsutil usn deletejournal' (ou chkdsk/erro de disco)")
		}),
		etapaSimuladaSimples("Historico dos navegadores", "HISTORICO DOS NAVEGADORES", func(c *Contexto) {
			c.R.Linha("Chrome (Default) de jogador: 0 paginas, 0 downloads, 0 pesquisas. Mais antiga: desconhecido  Mais recente: desconhecido")
			c.R.Add(Alerta, "Chrome (Default) de jogador com historico VAZIO", "Historico limpo ou navegador nunca usado")
		}),
		etapaSimuladaSimples("Discord", "DISCORD (cache, armazenamento local e anexos)", func(c *Contexto) {
			c.R.Linha("discord de jogador: 11 arquivos (2 MB) analisados em C:\\Users\\jogador\\AppData\\Roaming\\discord")
			c.R.Add(Alerta, "Cache do discord de jogador quase vazio (11 arquivos)", "Cache do Discord limpo recentemente. Quem limpa o cache do Discord antes de uma checagem esta escondendo algo")
		}),
		{"Varredura de arquivos", func(c *Contexto) {
			c.R.Secao("VARREDURA DE ARQUIVOS")
			c.R.Linha("120310 arquivos analisados em 1m02s")
			c.R.Add(Alerta, "Arquivo bate com assinatura 'ccleaner': CCleaner64.exe", "C:\\Program Files\\CCleaner\\CCleaner64.exe\nmodificado: "+formataHora(time.Now().Add(-2*time.Hour))+"  tamanho: 31220 KB")
			pausaSimulada(300 * time.Millisecond)
		}, true},
		{"Strings de cheat no conteudo dos arquivos", func(c *Contexto) {
			c.R.Secao("STRINGS DE CHEAT NO CONTEUDO DOS ARQUIVOS")
			c.R.Linha("39800 arquivos (2900 MB) lidos em 1m40s")
			c.R.Ok("Nenhum arquivo com string de cheat no conteudo")
			pausaSimulada(300 * time.Millisecond)
		}, true},
	}
}

func etapasSimuladasFechou() []Etapa {
	jogo := time.Now().Add(-2 * time.Hour)
	cheat := time.Now().Add(-95 * time.Minute)
	taskmgr := time.Now().Add(-4 * time.Minute)
	return []Etapa{
		{"Sistema e integridade de codigo", func(c *Contexto) {
			r := c.R
			cabecalhoSimulado(c, false)
			r.Ok("Integridade de codigo normal (drivers precisam de assinatura)")
			r.Ok("Secure Boot ligado")
			r.Ok("Prefetch habilitado (EnablePrefetcher=3)")
			pausaSimulada(300 * time.Millisecond)
		}, false},
		etapaSimuladaSimples("Origem do Windows (original ou modificado)", "ORIGEM DO WINDOWS (instalacao original ou modificada)", func(c *Contexto) {
			c.R.Linha("Edicao: Windows 11 Pro  build 26100")
			c.R.Ok("Windows com cara de instalacao original: servicos, arquivos e componentes de fabrica no lugar")
		}),
		etapaSimuladaSimples("Servicos de rastreio e protecao", "SERVICOS DO WINDOWS (rastreio e protecao)", func(c *Contexto) {
			c.R.Ok("Todos os servicos de rastreio e protecao estao ativos")
		}),
		etapaSimuladaSimples("Windows Defender", "WINDOWS DEFENDER", func(c *Contexto) {
			c.R.Ok("Defender ativo com protecao em tempo real")
			c.R.Add(Critico, "Exclusao no Defender: C:\\Users\\jogador\\AppData\\Local\\Temp", "Exclusao em pasta de download/temp/area de trabalho, padrao de loader de cheat. Exclusao de paths no Defender")
		}),
		etapaSimuladaSimples("Logs de eventos", "LOGS DE EVENTOS DO WINDOWS", func(c *Contexto) {
			c.R.Ok("Nenhum registro de limpeza do log Security (evento 1102)")
		}),
		etapaSimuladaSimples("ETW / kernel", "ETW / KERNEL (rastreamento do proprio Windows)", func(c *Contexto) {
			c.R.Ok("Sessoes ETW essenciais do Windows estao rodando (o sistema ainda registra eventos)")
			c.R.Linha("Captura do kernel: 4120 eventos em 21s (3502 carregamentos de imagem, 48 processos novos, 66 consultas DNS)")
			c.R.Ok("Teste ativo do ETW passou: o kernel registrou os 10 processos que o scanner iniciou de proposito")
			c.R.Linha("Nenhuma consulta DNS a dominio de cheat durante a captura (o loader ja estava fechado)")
		}),
		etapaSimuladaSimples("Historico de execucao no registro", "HISTORICO DE EXECUCAO (registro do Windows)", func(c *Contexto) {
			c.R.Linha("Entradas encontradas: BAM=96  UserAssist=180  PcaSvc Store=150  MuiCache=210  RecentDocs=64")
			c.R.Add(Critico, "Executado (BAM) bate com assinatura 'eulen': eulen_loader.exe", formataHora(cheat)+"  usuario: jogador\nC:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe")
			c.RegistraExecucao("C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe", cheat, "BAM")
			c.RegistraExecucao("C:\\Users\\jogador\\Downloads\\obs-studio.exe", jogo.Add(10*time.Minute), "BAM")
		}),
		etapaSimuladaSimples("Prefetch", "PREFETCH (programas executados)", func(c *Contexto) {
			c.R.Linha("451 arquivos .pf em C:\\Windows\\Prefetch")
			c.R.Add(Critico, "Prefetch de programa que bate com assinatura 'eulen': EULEN_LOADER.EXE", "Ultima execucao: "+formataHora(cheat)+"  (EULEN_LOADER.EXE-7A11C0F2.pf)")
			c.RegistraExecucao("EULEN_LOADER.EXE", cheat, "Prefetch")
		}),
		etapaSimuladaSimples("Artefatos do Windows (ShimCache, crashes, atalhos)", "ARTEFATOS DO WINDOWS (ShimCache, crashes, atalhos)", func(c *Contexto) {
			c.R.Linha("AppCompatCache (ShimCache): 690 executaveis registrados pelo Windows")
			c.R.Add(Critico, "ShimCache registrou execucao de arquivo com assinatura 'eulen': eulen_loader.exe", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe\nmodificado: "+formataHora(cheat)+"\nO ShimCache guarda o caminho mesmo que o arquivo tenha sido apagado e o Prefetch limpo")
			c.R.Add(Critico, "Atalho (.lnk) aponta para arquivo com assinatura 'eulen'", "C:\\Users\\jogador\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\eulen_loader.lnk\n"+formataHora(cheat))
			c.RegistraExecucao("C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe", cheat, "ShimCache")
		}),
		etapaSimuladaSimples("Arquivos recentes e lixeira", "ARQUIVOS RECENTES E LIXEIRA", func(c *Contexto) {
			c.R.Linha("Recentes de jogador: 148 atalhos, ultimo em %s", formataHora(time.Now().Add(-3*time.Minute)))
		}),
		{"Processos, handles, overlay e drivers", func(c *Contexto) {
			r := c.R
			r.Secao("PROCESSOS EM EXECUCAO (analise ponto a ponto)")
			r.Linha("174 processos em execucao")
			r.Progresso("Lendo versao, assinatura e hora de criacao de 174 processos")
			pausaSimulada(500 * time.Millisecond)
			processosSimulados(c, false)
			c.JogoAbriuEm = jogo
			c.TaskmgrAbertoEm = taskmgr
			r.Processo(9900, "Taskmgr.exe", "C:\\Windows\\System32\\Taskmgr.exe", "", "explorer.exe")
			r.Ok("Nenhum processo com nome de cheat, imitando o Windows, apagado, renomeado, adulterado ou fora de lugar")
			r.Add(Info, "Processos iniciados nos 15 minutos antes da checagem: 2", formataHora(taskmgr)+"  Taskmgr.exe  C:\\Windows\\System32\\Taskmgr.exe\n"+formataHora(time.Now().Add(-2*time.Minute))+"  chrome.exe  C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
			r.Ok("Lista de processos consistente entre Toolhelp, EnumProcesses e NtQuerySystemInformation (nada escondido)")
			r.Linha("2 handle(s) de outros processos apontando para o FiveM")
			r.Ok("Nenhum processo desconhecido com a memoria do FiveM aberta (cheat externo nao detectado)")
			r.Ok("Nenhuma janela overlay desconhecida nem janela com nome de cheat (212 janelas, tela 1920x1080)")
			r.Secao("DRIVERS DE KERNEL CARREGADOS")
			r.Ok("Nenhum driver vulneravel ou fora de lugar carregado. Drivers mapeados manualmente (kdmapper) nao aparecem nesta lista")
			pausaSimulada(320 * time.Millisecond)
		}, false},
		{"Memoria do jogo e linha do tempo", func(c *Contexto) {
			r := c.R
			r.Secao("MEMORIA DO JOGO E LINHA DO TEMPO DA SESSAO")
			r.Progresso("Lendo a memoria de FiveM_b3095_GTAProcess.exe (PID 6210) atras de codigo injetado")
			pausaSimulada(600 * time.Millisecond)
			r.Progresso("120 regioes executaveis lidas (240 MB) na memoria do jogo")
			pausaSimulada(600 * time.Millisecond)
			r.Linha("FiveM_b3095_GTAProcess.exe (PID 6210): 214 regioes executaveis fora de dll registrada, 388 MB lidos em 24s")
			r.Add(Critico, "1 modulo(s) carregado(s) na marra dentro de FiveM_b3095_GTAProcess.exe (manual map)", "Foram encontradas regioes de memoria privadas, executaveis e com cabecalho de programa (PE) que nao correspondem a nenhuma dll registrada.\nE assim que kdmapper e injetores modernos carregam cheat: a dll roda dentro do jogo sem aparecer na lista de modulos e sem precisar de arquivo no disco.\nFechar o programa do cheat pelo Gerenciador de Tarefas nao remove isso")
			r.Add(Critico, "String de cheat 'eulen' NA MEMORIA do jogo", "Regiao 0x1F4A0000000 (412 KB, RX, privada (sem arquivo)) dentro de FiveM_b3095_GTAProcess.exe\n...Eulen | auth.eulen.cc | session expired...\nA string esta na memoria do jogo agora. Isso vale mesmo que o programa do cheat ja tenha sido fechado, porque a dll injetada continua carregada")
			r.Add(Alerta, "3 regiao(oes) de memoria gravavel e executavel (RWX) em FiveM_b3095_GTAProcess.exe", "Memoria que pode ser escrita e executada ao mesmo tempo e rara em programa normal e comum em codigo injetado. Motores de script (V8, Lua JIT) tambem usam, entao sozinho nao prova nada")
			r.Linha("Jogo aberto desde %s (2h0m0s de sessao), 4 execucoes conhecidas para cruzar", formataHora(jogo))
			r.Add(Critico, "1 programa(s) com nome de cheat rodaram DEPOIS que o jogo abriu", "O jogo abriu em "+formataHora(jogo)+" e continua aberto agora.\n[eulen] "+formataHora(cheat)+"  C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe  (BAM)\nEsses programas rodaram com o jogo ja aberto. Fechar o programa antes da checagem nao apaga esse registro")
			r.Add(Critico, "Gerenciador de Tarefas foi aberto pouco antes da checagem", "Gerenciador de Tarefas aberto em "+formataHora(taskmgr)+".\nUm programa com nome de cheat rodou em "+formataHora(cheat)+", ou seja, ANTES de o Gerenciador ser aberto e antes desta checagem.\nEsse e o padrao de quem foi chamado para telagem e fechou o cheat pelo Gerenciador na hora")
			r.Add(Info, "Programas fora do Windows executados nas ultimas 6 horas: 3", formataHora(cheat)+"  C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe  (BAM)\n"+formataHora(jogo.Add(10*time.Minute))+"  C:\\Users\\jogador\\Downloads\\obs-studio.exe  (BAM)")
			pausaSimulada(340 * time.Millisecond)
		}, false},
		etapaSimuladaSimples("Hardware (DMA, KMBox, aim assist)", "HARDWARE (placa DMA, KMBox, dispositivos de aim assist)", func(c *Contexto) {
			c.R.Ok("Nenhuma placa DMA/FPGA nem dispositivo de aim assist (KMBox, MAKCU, Xim, Cronus, Arduino) no historico de hardware")
		}),
		etapaSimuladaSimples("FiveM", "FIVEM", func(c *Contexto) {
			c.R.Linha("Instalacao de jogador: C:\\Users\\jogador\\AppData\\Local\\FiveM\\FiveM.app")
			c.R.Add(Critico, "Log do FiveM menciona assinatura de cheat", "[eulen] [   482375] Loading module: eulen.dll")
		}),
		etapaSimuladaSimples("Cache DNS e journal USN", "CACHE DNS (sites acessados desde o boot)", func(c *Contexto) {
			c.R.Linha("96 nomes unicos no cache DNS")
			c.R.Add(Critico, "Cache DNS tem dominio de cheat ('eulen.cc'): api.eulen.cc", "O PC resolveu esse dominio desde o ultimo boot. O cache guarda mesmo depois do programa fechar")
		}),
		etapaSimuladaSimples("Historico dos navegadores", "HISTORICO DOS NAVEGADORES", func(c *Contexto) {
			c.R.Linha("Chrome (Default) de jogador: 3210 paginas, 60 downloads, 220 pesquisas. Mais antiga: %s  Mais recente: %s", formataHora(time.Now().Add(-40*24*time.Hour)), formataHora(time.Now().Add(-1*time.Hour)))
			c.R.Add(Critico, "Chrome (Default): CONTA SALVA em site de cheat ('eulen.cc')", formataHora(time.Now().Add(-20*24*time.Hour))+"  https://eulen.cc/login  jogador_br\nConta salva significa que o jogador criou login no site, nao apenas visitou")
		}),
		etapaSimuladaSimples("Discord", "DISCORD (cache, armazenamento local e anexos)", func(c *Contexto) {
			c.R.Linha("discord de jogador: 2180 arquivos (620 MB) analisados")
			c.R.Add(Critico, "Anexo do Discord bate com 'eulen': eulen_loader_v3.exe", "https://cdn.discordapp.com/attachments/1140022/1180331/eulen_loader_v3.exe")
		}),
		{"Varredura de arquivos", func(c *Contexto) {
			c.R.Secao("VARREDURA DE ARQUIVOS")
			c.R.Linha("162004 arquivos analisados em 1m18s")
			c.R.Add(Critico, "Arquivo bate com assinatura 'eulen': eulen_loader.exe", "C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe\nmodificado: "+formataHora(cheat)+"  tamanho: 3120 KB\nO arquivo continua no disco: fechar o processo nao apaga o executavel")
			pausaSimulada(300 * time.Millisecond)
		}, true},
		{"Strings de cheat no conteudo dos arquivos", func(c *Contexto) {
			c.R.Secao("STRINGS DE CHEAT NO CONTEUDO DOS ARQUIVOS")
			c.R.Linha("61200 arquivos (4010 MB) lidos em 2m02s")
			c.R.Add(Critico, "Executavel/script contem string 'eulen' (+1: eulen.cc): eulen_loader.exe", formataHora(cheat)+"  3120 KB  C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe\n...Eulen Loader - auth.eulen.cc - session...")
			pausaSimulada(300 * time.Millisecond)
		}, true},
	}
}

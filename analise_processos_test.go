package main

import (
	"strings"
	"testing"
	"time"
)

func sinaisTem(sinais []Sinal, sev Severidade, trecho string) bool {
	for _, s := range sinais {
		if s.Severidade == sev && strings.Contains(strings.ToLower(s.Titulo+" "+s.Detalhe), strings.ToLower(trecho)) {
			return true
		}
	}
	return false
}

func TestProcessoLegitimoNaoGeraSinal(t *testing.T) {
	a := assinaturasDeTeste(t)
	agora := time.Now()
	legitimos := []InfoProcesso{
		{PID: 812, Nome: "svchost.exe", Caminho: `C:\Windows\System32\svchost.exe`, PaiNome: "services.exe", OriginalFilename: "svchost.exe", CaminhoLido: true, ExisteNoDisco: true, Assinatura: "Valid", CriadoEm: agora.Add(-3 * time.Hour)},
		{PID: 2210, Nome: "Discord.exe", Caminho: `C:\Users\dom\AppData\Local\Discord\app-1.0.9200\Discord.exe`, PaiNome: "explorer.exe", OriginalFilename: "Discord.exe", ProductName: "Discord", CompanyName: "Discord Inc.", CaminhoLido: true, ExisteNoDisco: true, Assinatura: "Valid", CriadoEm: agora.Add(-2 * time.Hour)},
		{PID: 3100, Nome: "Code.exe", Caminho: `C:\Users\dom\AppData\Local\Programs\Microsoft VS Code\Code.exe`, PaiNome: "explorer.exe", OriginalFilename: "electron.exe", ProductName: "Visual Studio Code", CaminhoLido: true, ExisteNoDisco: true, Assinatura: "Valid"},
		{PID: 6210, Nome: "FiveM_b3095_GTAProcess.exe", Caminho: `C:\Users\dom\AppData\Local\FiveM\FiveM.app\FiveM_b3095_GTAProcess.exe`, PaiNome: "FiveM.exe", OriginalFilename: "FiveM_GTAProcess.exe", CaminhoLido: true, ExisteNoDisco: true, Assinatura: "Valid"},
		{PID: 3510, Nome: "MsMpEng.exe", Caminho: "", CaminhoLido: false},
		{PID: 4100, Nome: "NVIDIA_app_v11.0.6.383.exe", Caminho: `C:\Users\dom\Downloads\NVIDIA_app_v11.0.6.383.exe`, PaiNome: "explorer.exe", OriginalFilename: "NVIDIA App Installer", CaminhoLido: true, ExisteNoDisco: true, Assinatura: "Valid"},
		{PID: 4200, Nome: "conhost.exe", Caminho: `C:\Windows\System32\conhost.exe`, PaiNome: "cmd.exe", OriginalFilename: "CONHOST.EXE", CaminhoLido: true, ExisteNoDisco: true},
		{PID: 4300, Nome: "FiveM_b3095_DumpServer.exe", Caminho: `C:\Users\dom\AppData\Local\FiveM\FiveM.app\FiveM_b3095_DumpServer.exe`, PaiNome: "FiveM_b3095_GTAProcess.exe", CaminhoLido: true, ExisteNoDisco: true},
	}
	for _, info := range legitimos {
		for _, s := range avaliarProcesso(info, a, agora) {
			if s.Severidade != Info {
				t.Errorf("%s nao devia gerar sinal %s: %s", info.Nome, s.Severidade, s.Titulo)
			}
		}
	}
}

func TestProcessoImitandoWindows(t *testing.T) {
	a := assinaturasDeTeste(t)
	agora := time.Now()
	s := avaliarProcesso(InfoProcesso{PID: 9001, Nome: "svchost.exe", Caminho: `C:\Users\dom\AppData\Roaming\svchost.exe`, PaiNome: "explorer.exe", CaminhoLido: true, ExisteNoDisco: true}, a, agora)
	if !sinaisTem(s, Critico, "se passando por processo do Windows") {
		t.Errorf("svchost fora do System32 devia ser critico: %+v", s)
	}
	s = avaliarProcesso(InfoProcesso{PID: 9002, Nome: "svch0st.exe", Caminho: `C:\Windows\System32\svch0st.exe`, PaiNome: "services.exe", CaminhoLido: true, ExisteNoDisco: true}, a, agora)
	if !sinaisTem(s, Critico, "IMITANDO") {
		t.Errorf("svch0st devia ser typosquat critico: %+v", s)
	}
	s = avaliarProcesso(InfoProcesso{PID: 9003, Nome: "svchost.exe", Caminho: `C:\Windows\System32\svchost.exe`, PaiNome: "explorer.exe", CaminhoLido: true, ExisteNoDisco: true}, a, agora)
	if !sinaisTem(s, Critico, "iniciado por explorer.exe") {
		t.Errorf("svchost filho de explorer devia ser critico: %+v", s)
	}
}

func TestProcessoApagadoRenomeadoEAdulterado(t *testing.T) {
	a := assinaturasDeTeste(t)
	agora := time.Now()
	s := avaliarProcesso(InfoProcesso{PID: 9010, Nome: "update.exe", Caminho: `C:\Users\dom\AppData\Local\Temp\update.exe`, PaiNome: "explorer.exe", CaminhoLido: true, ExisteNoDisco: false}, a, agora)
	if !sinaisTem(s, Critico, "APAGADO enquanto ainda roda") {
		t.Errorf("exe apagado devia ser critico: %+v", s)
	}
	s = avaliarProcesso(InfoProcesso{PID: 9011, Nome: "notepad2.exe", Caminho: `C:\Users\dom\Desktop\notepad2.exe`, PaiNome: "explorer.exe", OriginalFilename: "cheatengine-x86_64.exe", ProductName: "Cheat Engine", CaminhoLido: true, ExisteNoDisco: true}, a, agora)
	if !sinaisTem(s, Critico, "RENOMEADA") {
		t.Errorf("cheat engine renomeado devia ser critico: %+v", s)
	}
	s = avaliarProcesso(InfoProcesso{PID: 9012, Nome: "launcher.exe", Caminho: `C:\Users\dom\Downloads\launcher.exe`, PaiNome: "explorer.exe", OriginalFilename: "hydra_loader.exe", ProductName: "", CaminhoLido: true, ExisteNoDisco: true}, a, agora)
	if !sinaisTem(s, Alerta, "renomeado") {
		t.Errorf("exe renomeado em Downloads devia ser alerta: %+v", s)
	}
	s = avaliarProcesso(InfoProcesso{PID: 9013, Nome: "Discord.exe", Caminho: `C:\Users\dom\AppData\Local\Discord\app-1.0.9200\Discord.exe`, PaiNome: "explorer.exe", CaminhoLido: true, ExisteNoDisco: true, Assinatura: "HashMismatch"}, a, agora)
	if !sinaisTem(s, Critico, "ASSINADO MAS ALTERADO") {
		t.Errorf("hash mismatch devia ser critico: %+v", s)
	}
	s = avaliarProcesso(InfoProcesso{PID: 9014, Nome: "ldr.exe", Caminho: `C:\Users\dom\AppData\Local\Temp\ldr.exe`, PaiNome: "explorer.exe", CaminhoLido: true, ExisteNoDisco: true, Assinatura: "NotSigned"}, a, agora)
	if !sinaisTem(s, Alerta, "SEM assinatura digital") {
		t.Errorf("nao assinado em Temp devia ser alerta: %+v", s)
	}
}

func TestProcessoFilhoDoFiveMEControleRemoto(t *testing.T) {
	a := assinaturasDeTeste(t)
	agora := time.Now()
	s := avaliarProcesso(InfoProcesso{PID: 9020, Nome: "cmd.exe", Caminho: `C:\Windows\System32\cmd.exe`, PaiNome: "FiveM_b3095_GTAProcess.exe", CaminhoLido: true, ExisteNoDisco: true}, a, agora)
	if !sinaisTem(s, Critico, "DE DENTRO do FiveM") {
		t.Errorf("cmd filho do FiveM devia ser critico: %+v", s)
	}
	s = avaliarProcesso(InfoProcesso{PID: 9021, Nome: "AnyDesk.exe", Caminho: `C:\Program Files (x86)\AnyDesk\AnyDesk.exe`, PaiNome: "explorer.exe", CaminhoLido: true, ExisteNoDisco: true, Assinatura: "Valid"}, a, agora)
	if !sinaisTem(s, Alerta, "Controle remoto ATIVO") {
		t.Errorf("anydesk devia ser alerta: %+v", s)
	}
	s = avaliarProcesso(InfoProcesso{PID: 9022, Nome: "CCleaner64.exe", Caminho: `C:\Program Files\CCleaner\CCleaner64.exe`, PaiNome: "explorer.exe", CaminhoLido: true, ExisteNoDisco: true, Assinatura: "Valid", CriadoEm: agora.Add(-4 * time.Minute)}, a, agora)
	if !sinaisTem(s, Critico, "Limpador 'ccleaner' aberto") {
		t.Errorf("ccleaner aberto 4 min antes devia ser critico: %+v", s)
	}
	s = avaliarProcesso(InfoProcesso{PID: 9023, Nome: "vgc.exe", Caminho: "", CaminhoLido: false}, a, agora)
	if len(s) != 0 {
		t.Errorf("vgc (vanguard) protegido e conhecido, nao devia gerar sinal: %+v", s)
	}
	s = avaliarProcesso(InfoProcesso{PID: 9024, Nome: "xyz.exe", Caminho: "", CaminhoLido: false}, a, agora)
	if len(s) != 0 {
		t.Errorf("processo sem caminho sozinho nao e sinal, so entra na lista informativa: %+v", s)
	}
}

func TestHandlesNoFiveM(t *testing.T) {
	a := assinaturasDeTeste(t)
	handles := []HandleNoFiveM{
		{DonoPID: 100, DonoNome: "obs64.exe", DonoCaminho: `C:\Program Files\obs-studio\bin\64bit\obs64.exe`, Acesso: acessoVMRead | 0x400},
		{DonoPID: 101, DonoNome: "Discord.exe", DonoCaminho: `C:\Users\dom\AppData\Local\Discord\app-1\Discord.exe`, Acesso: acessoAllAccess},
		{DonoPID: 102, DonoNome: "svchost.exe", DonoCaminho: `C:\Windows\System32\svchost.exe`, Acesso: acessoAllAccess},
		{DonoPID: 103, DonoNome: "ext.exe", DonoCaminho: `C:\Users\dom\Desktop\ext.exe`, Acesso: acessoVMRead | acessoVMWrite | acessoVMOperation},
		{DonoPID: 104, DonoNome: "reader.exe", DonoCaminho: `C:\Users\dom\AppData\Roaming\x\reader.exe`, Acesso: acessoVMRead | 0x400},
		{DonoPID: 105, DonoNome: "eulen_loader.exe", DonoCaminho: `C:\Users\dom\AppData\Local\Temp\eulen_loader.exe`, Acesso: acessoVMRead},
	}
	s := avaliarHandlesNoFiveM(handles, a)
	if !sinaisTem(s, Critico, "ESCRITA na memoria do FiveM: ext.exe") {
		t.Errorf("ext.exe com VM_WRITE devia ser critico: %+v", s)
	}
	if !sinaisTem(s, Alerta, "LENDO a memoria do FiveM: reader.exe") {
		t.Errorf("reader.exe devia ser alerta: %+v", s)
	}
	if !sinaisTem(s, Critico, "'eulen' tem handle") {
		t.Errorf("eulen devia ser critico por assinatura: %+v", s)
	}
	for _, aceito := range []string{"obs64", "Discord.exe", "svchost"} {
		if sinaisTem(s, Critico, aceito) || sinaisTem(s, Alerta, aceito) {
			t.Errorf("%s e dono aceito e nao devia ser flagrado: %+v", aceito, s)
		}
	}
}

func TestJanelasOverlay(t *testing.T) {
	a := assinaturasDeTeste(t)
	janelas := []JanelaVista{
		{PID: 1, DonoNome: "Discord.exe", DonoCaminho: `C:\Users\dom\AppData\Local\Discord\Discord.exe`, Titulo: "Discord Overlay", Classe: "Chrome_WidgetWin_1", Largura: 1920, Altura: 1080, Layered: true, Transparente: true, Topmost: true, Visivel: true},
		{PID: 2, DonoNome: "esp.exe", DonoCaminho: `C:\Users\dom\Desktop\esp.exe`, Titulo: "", Classe: "ImGui Overlay", Largura: 1920, Altura: 1080, Layered: true, Transparente: true, Topmost: true, Visivel: true},
		{PID: 3, DonoNome: "notepad.exe", DonoCaminho: `C:\Windows\System32\notepad.exe`, Titulo: "Sem titulo - Bloco de Notas", Classe: "Notepad", Largura: 800, Altura: 600, Visivel: true},
		{PID: 4, DonoNome: "app.exe", DonoCaminho: `C:\Users\dom\Desktop\app.exe`, Titulo: "Eulen v3.2 - Menu", Classe: "WindowsForms10", Largura: 400, Altura: 300, Visivel: false},
		{PID: 5, DonoNome: "small.exe", DonoCaminho: `C:\Users\dom\Desktop\small.exe`, Titulo: "", Classe: "X", Largura: 300, Altura: 200, Layered: true, Transparente: true, Topmost: true, Visivel: true},
	}
	s := avaliarJanelas(janelas, 1920, 1080, a)
	if !sinaisTem(s, Critico, "OVERLAY transparente cobrindo a tela inteira: esp.exe") {
		t.Errorf("overlay do esp.exe devia ser critico: %+v", s)
	}
	if !sinaisTem(s, Critico, "Janela com nome de cheat ('eulen')") {
		t.Errorf("janela Eulen devia ser critico mesmo escondida: %+v", s)
	}
	for _, aceito := range []string{"Discord", "notepad", "small.exe"} {
		if sinaisTem(s, Critico, aceito) || sinaisTem(s, Alerta, aceito) {
			t.Errorf("%s nao devia ser flagrado: %+v", aceito, s)
		}
	}
}

func TestDispositivosDMAeKMBox(t *testing.T) {
	a := assinaturasDeTeste(t)
	dispositivos := []DispositivoVisto{
		{Classe: "PCI", Descricao: "Xilinx Development System", HardwareID: `PCI\VEN_10EE&DEV_7022\4&abc`, Presente: true},
		{Classe: "USB", Descricao: "USB-SERIAL CH340", HardwareID: `USB\VID_1A86&PID_7523\5&1`, Presente: true},
		{Classe: "HID", Descricao: "KMBOX NET", HardwareID: `HID\VID_1A86&PID_E026\7&2`, Presente: false},
		{Classe: "PCI", Descricao: "NVIDIA GeForce RTX 4070", HardwareID: `PCI\VEN_10DE&DEV_2786\4&x`, Presente: true},
		{Classe: "USB", Descricao: "Arduino Leonardo", HardwareID: `USB\VID_2341&PID_8036\6&3`, Presente: true},
	}
	s := avaliarDispositivos(dispositivos, a)
	if !sinaisTem(s, Critico, "Placa DMA/FPGA detectada ('xilinx')") {
		t.Errorf("xilinx devia ser critico: %+v", s)
	}
	if !sinaisTem(s, Alerta, "KMBOX NET") {
		t.Errorf("kmbox desconectado devia ser alerta: %+v", s)
	}
	if !sinaisTem(s, Critico, "Arduino Leonardo") {
		t.Errorf("arduino leonardo conectado devia ser critico: %+v", s)
	}
	if sinaisTem(s, Critico, "NVIDIA") || sinaisTem(s, Alerta, "NVIDIA") || sinaisTem(s, Critico, "CH340") || sinaisTem(s, Alerta, "CH340") {
		t.Errorf("placa de video e ch340 generico nao deviam ser flagrados: %+v", s)
	}
}

func TestExclusaoDeDefenderPorTipoDePasta(t *testing.T) {
	for _, caso := range []struct {
		caminho string
		dev     bool
	}{
		{`C:\Users\Dom\AppData\Local\JetBrains\IntelliJIdea2024.2`, true},
		{`D:\SDG\Projetos\deploy-panel`, true},
		{`C:\Users\Dom\AppData\Local\Android\Sdk`, true},
		{`C:\Users\Dom\AppData\Local\Temp`, false},
		{`C:\Users\Dom\Downloads`, false},
	} {
		if pastaDeDesenvolvimento(strings.ToLower(caso.caminho)) != caso.dev {
			t.Errorf("%s: esperava dev=%v", caso.caminho, caso.dev)
		}
	}
}

func TestScriptDoSistemaOuDoScanner(t *testing.T) {
	ruido := []string{
		`ScheduledTimeOnly')] [ValidateNotNull()] [ValidateNotNullOrEmpty()] [switch] ${SharedSignaturesPathUpdateAtScheduledTimeOnly}`,
		`[Parameter(ParameterSetName='Remove2')] [Alias('tfsso')] [switch] ${x}`,
		`[Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.SubmitSamplesConsentType] ${Submit}`,
		`Get-MpComputerStatus | Select-Object AMServiceEnabled`,
	}
	for _, texto := range ruido {
		if !scriptDoSistemaOuDoScanner(texto) {
			t.Errorf("devia ser ignorado como ruido do modulo do PowerShell: %q", texto)
		}
	}
	for _, texto := range []string{`Set-MpPreference -DisableRealtimeMonitoring $true`, `wevtutil cl Security`} {
		if scriptDoSistemaOuDoScanner(texto) {
			t.Errorf("comando real nao devia ser ignorado: %q", texto)
		}
	}
}

func TestCodeIntegrityIgnoraDllDeProgramaInstalado(t *testing.T) {
	a := assinaturasDeTeste(t)
	eventos := []EventoETW{
		{ID: 3033, Hora: time.Now(), Dados: map[string]string{"FileNameBuffer": `\Device\HarddiskVolume3\Program Files\Bonjour\mdnsNSP.dll`}},
		{ID: 3004, Hora: time.Now(), Dados: map[string]string{"FileNameBuffer": `\Device\HarddiskVolume3\ProgramData\Microsoft\Windows Defender\Platform\4.18\DefenderSessionHelper.exe`}},
		{ID: 3033, Hora: time.Now(), Dados: map[string]string{"FileNameBuffer": `\Device\HarddiskVolume3\Users\dom\AppData\Local\Temp\drv.sys`}},
	}
	s := avaliarEventosDeIntegridade(eventos, a)
	if sinaisTem(s, Critico, "mdnsNSP") || sinaisTem(s, Critico, "DefenderSessionHelper") {
		t.Errorf("dll de programa instalado nao devia ser critico: %+v", s)
	}
	if !sinaisTem(s, Critico, "drv.sys") {
		t.Errorf("driver nao assinado em Temp devia ser critico: %+v", s)
	}
}

func TestNomeDeBackupOuTemporarioNaoEhDisfarce(t *testing.T) {
	casos := map[string]bool{
		`VersionService.exe.bak`: true,
		`app.dll.old`:            true,
		`setup~1.tmp`:            true,
		`config.dat`:             false,
		`imagem.png`:             false,
	}
	for nome, esperado := range casos {
		if nomeDeBackupOuTemporario(nome, `D:\jogo\`+nome) != esperado {
			t.Errorf("%s: esperava %v", nome, esperado)
		}
	}
	if !nomeDeBackupOuTemporario("abc.tmp", `C:\Users\Dom\AppData\Local\Temp\abc.tmp`) {
		t.Errorf(".tmp dentro de Temp devia ser ignorado")
	}
}

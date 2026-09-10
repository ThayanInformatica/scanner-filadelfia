package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const csvUSN = `USN,File name,File name length,Reason,Time stamp,File attributes,File ID,Parent file ID,Source info,Security ID,Major version,Minor version,Record length
1000,eulen_loader.exe,32,File create,5/12/2026 21:03:11,32,0x1,0x2,0,0,3,0,96
1100,eulen_loader.exe,32,File delete| Close,5/12/2026 23:40:02,32,0x1,0x2,0,0,3,0,96
1200,relatorio.docx,28,File create,5/12/2026 21:05:00,32,0x3,0x2,0,0,3,0,96
1300,ghost_menu_v2.rar,34,File create| Close,6/01/2026 10:00:00,32,0x4,0x2,0,0,3,0,96
1400,chrome.exe,20,Data overwrite,6/01/2026 10:01:00,32,0x5,0x2,0,0,3,0,96
`

func TestLeituraDoJournalUSN(t *testing.T) {
	a := assinaturasDeTeste(t)
	interessa := func(nome string) bool {
		classe, _ := a.Classificar(nome)
		return classe != SemMatch
	}
	eventos, total, err := lerUSNCsv(strings.NewReader(csvUSN), 1000, interessa)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Errorf("esperava 5 registros lidos, veio %d", total)
	}
	if len(eventos) != 3 {
		t.Fatalf("esperava 3 eventos de interesse (2 eulen + 1 ghost menu), veio %d: %+v", len(eventos), eventos)
	}
	if eventos[1].Motivo != "apagado" {
		t.Errorf("segundo evento devia ser apagado: %+v", eventos[1])
	}
	if eventos[0].Hora.IsZero() {
		t.Errorf("hora nao foi lida: %+v", eventos[0])
	}
	sinais := avaliarUSN("C:", eventos, total, a)
	if !sinaisTem(sinais, Critico, "APAGADO do disco C:") {
		t.Errorf("devia apontar o eulen apagado: %+v", sinais)
	}
	if !sinaisTem(sinais, Critico, "ghost_menu_v2.rar") {
		t.Errorf("devia apontar o ghost menu: %+v", sinais)
	}
	for _, limpo := range []string{"relatorio.docx", "chrome.exe"} {
		if sinaisTem(sinais, Critico, limpo) || sinaisTem(sinais, Alerta, limpo) {
			t.Errorf("%s nao devia ser flagrado: %+v", limpo, sinais)
		}
	}
}

func TestTarefasAgendadas(t *testing.T) {
	a := assinaturasDeTeste(t)
	tarefas := []TarefaAgendada{
		{Nome: `\Microsoft\Windows\UpdateOrchestrator\Reboot`, Comando: `C:\Windows\System32\usoclient.exe`, Autor: "Microsoft"},
		{Nome: `\NVIDIA GeForce Experience SelfUpdate`, Comando: `C:\Program Files\NVIDIA Corporation\Update\update.exe`, Autor: "NVIDIA"},
		{Nome: `\eulen_start`, Comando: `C:\Users\dom\AppData\Local\Temp\eulen_loader.exe`, Autor: "dom", Estado: "Pronto"},
		{Nome: `\limpeza`, Comando: `powershell -c "wevtutil cl Security"`, Autor: "dom", Estado: "Pronto"},
		{Nome: `\updater`, Comando: `C:\Users\dom\AppData\Local\Temp\a9f31c7d4b.exe`, Autor: "dom", Estado: "Pronto"},
	}
	s := avaliarTarefas(tarefas, a)
	if !sinaisTem(s, Critico, "eulen") {
		t.Errorf("tarefa do eulen devia ser critica: %+v", s)
	}
	if !sinaisTem(s, Critico, "limpa log de eventos") {
		t.Errorf("tarefa de limpeza devia ser critica: %+v", s)
	}
	if !sinaisTem(s, Alerta, "nome aleatorio") {
		t.Errorf("tarefa com exe de nome aleatorio na Temp devia ser alerta: %+v", s)
	}
	for _, limpo := range []string{"UpdateOrchestrator", "NVIDIA"} {
		if sinaisTem(s, Critico, limpo) || sinaisTem(s, Alerta, limpo) {
			t.Errorf("%s nao devia ser flagrado: %+v", limpo, s)
		}
	}
}

func TestFluxosAlternativos(t *testing.T) {
	a := assinaturasDeTeste(t)
	streams := []StreamOculto{
		{Arquivo: `C:\Users\dom\Downloads\setup.exe`, Stream: ":Zone.Identifier:$DATA", Tamanho: 200},
		{Arquivo: `C:\Users\dom\Desktop\foto.jpg`, Stream: ":eulen:$DATA", Tamanho: 3 * 1024 * 1024},
		{Arquivo: `C:\Users\dom\Desktop\notas.txt`, Stream: ":payload:$DATA", Tamanho: 900 * 1024},
		{Arquivo: `C:\Users\dom\Desktop\a.txt`, Stream: ":anotacao:$DATA", Tamanho: 300},
	}
	s := avaliarStreamsOcultos(streams, a)
	if !sinaisTem(s, Critico, "eulen") {
		t.Errorf("ADS com nome de cheat devia ser critico: %+v", s)
	}
	if !sinaisTem(s, Alerta, "payload") {
		t.Errorf("ADS grande devia ser alerta: %+v", s)
	}
	if sinaisTem(s, Critico, "Zone.Identifier") || sinaisTem(s, Alerta, "Zone.Identifier") {
		t.Errorf("Zone.Identifier e normal: %+v", s)
	}
	if !sinaisTem(s, Info, "anotacao") {
		t.Errorf("ADS pequeno devia entrar como info: %+v", s)
	}
}

func TestMotivoUSNLegivel(t *testing.T) {
	casos := map[string]string{
		"File delete| Close":          "apagado",
		"File create":                 "criado",
		"Rename new name| Close":      "renomeado",
		"Data overwrite| Data extend": "escrito",
	}
	for entrada, esperado := range casos {
		if got := motivoUSNLegivel(entrada); got != esperado {
			t.Errorf("%q: esperava %q, veio %q", entrada, esperado, got)
		}
	}
}

func TestLixeiraComMarcaAntigaContinuaCritica(t *testing.T) {
	a := assinaturasDeTeste(t)
	if a.Marca("password_is_eulen.rar") == "" {
		t.Errorf("eulen devia ser reconhecido como marca, para nao ser rebaixado quando antigo")
	}
	antigo := time.Now().Add(-300 * 24 * time.Hour)
	if antigo.After(time.Now()) {
		t.Fatal("data de teste invalida")
	}
}

func TestSiteDeCompartilhamentoEArquivoDoJogo(t *testing.T) {
	casos := []struct {
		url, arquivo string
		site         string
		jogo         bool
	}{
		{"https://www.mediafire.com/file/x/citizen_com_agua.zip/file", "citizen com água.zip", "mediafire.com", true},
		{"https://drive.usercontent.google.com/download?id=x", "SOM PVP TEQUINHO.rar", "drive.usercontent.google.com", false},
		{"https://cdn.discordapp.com/attachments/1/2/scanner.exe", "scanner.exe", "cdn.discordapp.com", false},
		{"https://fivem.net/", "FiveM.exe", "", true},
		{"https://www.nvidia.com/pt-br/geforce/", "GeForce.exe", "", false},
	}
	for _, c := range casos {
		if got := ehSiteDeCompartilhamento(c.url); got != c.site {
			t.Errorf("%s: esperava site %q, veio %q", c.url, c.site, got)
		}
		if (arquivoDoUniversoDoJogo(c.arquivo) != "") != c.jogo {
			t.Errorf("%s: esperava jogo=%v", c.arquivo, c.jogo)
		}
	}
}

func TestConversaoDeSaidaDoWindows(t *testing.T) {
	cp1252 := string([]byte{'S', 'E', 'R', 'V', 'I', 0xC7, 'O', ' ', 'L', 'O', 'C', 'A', 'L'})
	if got := paraUTF8(cp1252); got != "SERVIÇO LOCAL" {
		t.Errorf("esperava SERVICO LOCAL acentuado, veio %q", got)
	}
	if got := paraUTF8("já é utf-8 válido"); got != "já é utf-8 válido" {
		t.Errorf("texto ja valido nao pode ser mexido, veio %q", got)
	}
}

func TestContaDeServicoDoWindows(t *testing.T) {
	for _, u := range []string{"LOCAL SERVICE", "SERVIÇO LOCAL", "SYSTEM", "SISTEMA", "NT AUTHORITY\\SYSTEM"} {
		if !contaDeServicoDoWindows(u) {
			t.Errorf("%q devia ser conta de servico", u)
		}
	}
	for _, u := range []string{"parul", "Dom", "jogador"} {
		if contaDeServicoDoWindows(u) {
			t.Errorf("%q e usuario de verdade", u)
		}
	}
}

func TestIntegridadeDoFiveM(t *testing.T) {
	a := assinaturasDeTeste(t)
	arquivos := []ArquivoDoJogo{
		{Nome: "FiveM.exe", Caminho: `C:\FiveM.app\FiveM.exe`, Assinatura: "Valid", Assinante: "CN=the CitizenFX Collective", NaRaiz: true},
		{Nome: "CitizenGame.dll", Caminho: `C:\FiveM.app\CitizenGame.dll`, Assinatura: "Valid", Assinante: "CN=the CitizenFX Collective", NaRaiz: true},
		{Nome: "CoreRT.dll", Caminho: `C:\FiveM.app\CoreRT.dll`, Assinatura: "Valid", Assinante: "CN=the CitizenFX Collective", NaRaiz: true},
		{Nome: "botao.dll", Caminho: `C:\FiveM.app\botao.dll`, Assinatura: "NotSigned", NaRaiz: true, Tamanho: 900 * 1024},
		{Nome: "citizen-scripting-lua.dll", Caminho: `C:\FiveM.app\citizen-scripting-lua.dll`, Assinatura: "HashMismatch", Assinante: "CN=the CitizenFX Collective", NaRaiz: true},
	}
	s := avaliarIntegridadeDoJogo(`C:\FiveM.app`, arquivos, a)
	if !sinaisTem(s, Critico, "ASSINADO MAS ALTERADO") {
		t.Errorf("dll do FiveM adulterada devia ser critico: %+v", s)
	}
	if !sinaisTem(s, Alerta, "botao.dll") {
		t.Errorf("dll sem assinatura no meio de assinadas devia ser alerta: %+v", s)
	}
	limpos := []ArquivoDoJogo{
		{Nome: "FiveM.exe", Caminho: `C:\a\FiveM.exe`, Assinatura: "Valid", Assinante: "CN=the CitizenFX Collective", NaRaiz: true},
		{Nome: "CoreRT.dll", Caminho: `C:\a\CoreRT.dll`, Assinatura: "Valid", Assinante: "CN=the CitizenFX Collective", NaRaiz: true},
	}
	if s := avaliarIntegridadeDoJogo(`C:\a`, limpos, a); len(s) != 0 {
		t.Errorf("pasta integra nao devia gerar sinal: %+v", s)
	}
}

func TestPastaDoGTAComMods(t *testing.T) {
	a := assinaturasDeTeste(t)
	arquivos := []ArquivoDoJogo{
		{Nome: "GTA5.exe", Caminho: `D:\GTAV\GTA5.exe`, Assinatura: "Valid", Assinante: "CN=Rockstar Games, Inc."},
		{Nome: "dinput8.dll", Caminho: `D:\GTAV\dinput8.dll`, Assinatura: "NotSigned"},
		{Nome: "OpenIV.asi", Caminho: `D:\GTAV\OpenIV.asi`, Assinatura: "NotSigned"},
		{Nome: "eulen.asi", Caminho: `D:\GTAV\eulen.asi`, Assinatura: "NotSigned"},
		{Nome: "d3d11.dll", Caminho: `D:\GTAV\d3d11.dll`, Assinatura: "Valid", Assinante: "CN=Microsoft Windows"},
	}
	s := avaliarPastaDoGTA(`D:\GTAV`, arquivos, a)
	if !sinaisTem(s, Critico, "eulen") {
		t.Errorf("asi de cheat devia ser critico: %+v", s)
	}
	if !sinaisTem(s, Alerta, "dinput8.dll") {
		t.Errorf("dinput8 sem assinatura devia ser alerta: %+v", s)
	}
	if !sinaisTem(s, Alerta, "plugin(s) .asi") {
		t.Errorf("asi devia ser listado: %+v", s)
	}
	if sinaisTem(s, Alerta, "d3d11.dll") || sinaisTem(s, Critico, "GTA5.exe") {
		t.Errorf("dll assinada da Microsoft e o exe do jogo nao devem ser flagrados: %+v", s)
	}
}

func TestLocalDaInstalacaoEVirtualizacao(t *testing.T) {
	if s := avaliarLocalDaInstalacao(`C:\Users\parul\Downloads\FiveM.app`); !sinaisTem(s, Alerta, "fora do padrao") {
		t.Errorf("FiveM em Downloads devia ser alerta: %+v", s)
	}
	if s := avaliarLocalDaInstalacao(`C:\Users\dom\AppData\Local\FiveM\FiveM.app`); len(s) != 0 {
		t.Errorf("local padrao nao devia gerar sinal: %+v", s)
	}
	vms := []SinalDeVirtualizacao{{Fonte: "BIOS/SystemManufacturer", Valor: "VMware, Inc.", Marca: "vmware"}}
	if s := avaliarVirtualizacao(vms); !sinaisTem(s, Critico, "MAQUINA VIRTUAL") {
		t.Errorf("VM devia ser critico: %+v", s)
	}
	if s := avaliarVirtualizacao(nil); len(s) != 0 {
		t.Errorf("sem VM nao ha sinal: %+v", s)
	}
}

func TestExtracaoDeCaminhosDosAchados(t *testing.T) {
	casos := []struct {
		texto    string
		esperado []string
	}{
		{`C:\Users\parul\AppData\Roaming\Microsoft\Windows\Recent\Config Legit Pa Não Toma Ban.lnk`,
			[]string{`C:\Users\parul\AppData\Roaming\Microsoft\Windows\Recent\Config Legit Pa Não Toma Ban.lnk`}},
		{"C:\\Users\\jogador\\AppData\\Local\\Temp\\eulen_loader.exe\nmodificado: 09/09/2026  tamanho: 3120 KB",
			[]string{`C:\Users\jogador\AppData\Local\Temp\eulen_loader.exe`}},
		{`09/09/2026 10:58:42      385 KB  C:\WINDOWS\Temp\gcapi.dll`,
			[]string{`C:\WINDOWS\Temp\gcapi.dll`}},
		{`D:\Downloads Microsoft Edge\scanner.exe  <- https://cdn.discordapp.com/x/y.exe`,
			[]string{`D:\Downloads Microsoft Edge\scanner.exe`}},
		{`C:\Users\dom\Downloads\loader_v2.rar  (deletado em 03/05/2025 19:02:17)`,
			[]string{`C:\Users\dom\Downloads\loader_v2.rar`}},
		{`D:\SteamLibrary\steamapps\common\Grand Theft Auto V\dinput8.dll  (412 KB, 09/09/2026)`,
			[]string{`D:\SteamLibrary\steamapps\common\Grand Theft Auto V\dinput8.dll`}},
	}
	for _, c := range casos {
		got := caminhosNoTexto(c.texto)
		if len(got) != len(c.esperado) {
			t.Errorf("%q: esperava %d caminho(s), veio %v", resumeTexto(c.texto, 50), len(c.esperado), got)
			continue
		}
		for i := range got {
			if got[i] != c.esperado[i] {
				t.Errorf("esperava %q, veio %q", c.esperado[i], got[i])
			}
		}
	}
	semCaminho := []string{
		`[Volume3]\Windows\System32\cmd.exe`,
		`\Device\HarddiskVolume3\Users\dom\drv.sys`,
		`Nenhum arquivo com string de cheat no conteudo`,
		`https://eulen.cc/login`,
	}
	for _, texto := range semCaminho {
		if got := caminhosNoTexto(texto); len(got) != 0 {
			t.Errorf("%q nao devia virar caminho clicavel: %v", texto, got)
		}
	}
	varios := caminhosNoTexto("C:\\a\\um.exe\nC:\\a\\dois.exe\nC:\\a\\um.exe")
	if len(varios) != 2 {
		t.Errorf("caminhos repetidos deviam ser unificados: %v", varios)
	}
}

func TestWindowsModificadoVsOriginal(t *testing.T) {
	original := EstadoDoWindows{Edicao: "Windows 11 Pro", Build: "26100", DefenderResponde: true}
	if s := avaliarWindowsModificado(original); len(s) != 0 {
		t.Errorf("Windows original nao devia gerar sinal: %+v", s)
	}

	semDefender := EstadoDoWindows{
		Edicao:               "Windows 10 Pro",
		Build:                "26200",
		ServicosAusentes:     []string{"WinDefend (Microsoft Defender Antivirus)", "SecurityHealthService (Central de Seguranca do Windows)", "Sense (Defender ATP)"},
		ArquivosAusentes:     []string{"MsMpEng.exe (motor do Defender)", "SecurityHealthService.exe (Central de Seguranca)", "smartscreen.exe (SmartScreen)"},
		ComponentesRemovidos: []string{"o comando do Defender (Get-MpComputerStatus) nao existe neste Windows"},
	}
	s := avaliarWindowsModificado(semDefender)
	if !sinaisTem(s, Critico, "Defender foi REMOVIDO") {
		t.Errorf("Defender removido devia ser critico: %+v", s)
	}
	if !sinaisTem(s, Critico, "NAO E ORIGINAL") {
		t.Errorf("varios sinais deviam concluir Windows modificado: %+v", s)
	}

	comMarca := EstadoDoWindows{MarcasDeISO: []string{"Ghost Spectre em BuildLab"}}
	if s := avaliarWindowsModificado(comMarca); !sinaisTem(s, Critico, "NAO E ORIGINAL") {
		t.Errorf("marca de ISO sozinha ja fecha o caso: %+v", s)
	}

	umSinalSo := EstadoDoWindows{ServicosAusentes: []string{"WSearch (Windows Search)"}}
	s = avaliarWindowsModificado(umSinalSo)
	if sinaisTem(s, Critico, "NAO E ORIGINAL") {
		t.Errorf("um servico ausente sozinho nao fecha o caso: %+v", s)
	}
	if !sinaisTem(s, Alerta, "Windows alterado") {
		t.Errorf("um servico ausente devia virar alerta: %+v", s)
	}
}

func TestVirtualizacaoIgnoraHyperVDeFabrica(t *testing.T) {
	soHyperV := []SinalDeVirtualizacao{
		{Fonte: "servico do Windows", Valor: "VMBusHID", Marca: "vmbushid"},
		{Fonte: "servico do Windows", Valor: "hyperkbd", Marca: "hyperkbd"},
	}
	if s := avaliarVirtualizacaoForte(soHyperV); len(s) != 0 {
		t.Errorf("servico de Hyper-V existe em Windows normal, nao e VM: %+v", s)
	}
	comBios := append(soHyperV, SinalDeVirtualizacao{Fonte: "BIOS/SystemManufacturer", Valor: "VMware, Inc.", Marca: "vmware"})
	if s := avaliarVirtualizacaoForte(comBios); !sinaisTem(s, Critico, "MAQUINA VIRTUAL") {
		t.Errorf("BIOS de VMware devia acusar: %+v", s)
	}
}

func TestDonoDeHandleAceitoPorPrefixo(t *testing.T) {
	a := assinaturasDeTeste(t)
	handles := []HandleNoFiveM{
		{DonoPID: 200, DonoNome: "MedalEncoder.exe", DonoCaminho: `C:\Users\x\AppData\Local\Medal\recorder\MedalEncoder.exe`, Acesso: acessoAllAccess},
		{DonoPID: 201, DonoNome: "NVIDIA Share.exe", DonoCaminho: `C:\Program Files\NVIDIA Corporation\NVIDIA Share.exe`, Acesso: acessoVMRead},
	}
	if s := avaliarHandlesNoFiveM(handles, a); len(s) != 0 {
		t.Errorf("gravador e overlay conhecidos nao deviam acusar: %+v", s)
	}
}

func TestDownloadDeVideoNaoEhArquivoDoJogo(t *testing.T) {
	if arquivoDoUniversoDoJogo("MedalTVGrandTheftAutoVFiveM20260813135812054.mp4") != "" {
		t.Errorf("video de gameplay nao e arquivo do jogo")
	}
	if arquivoDoUniversoDoJogo("citizen com agua.zip") == "" {
		t.Errorf("zip do citizen e arquivo do jogo")
	}
}

func TestPacoteDeDriverNaoEhDisfarce(t *testing.T) {
	for _, caminho := range []string{
		`C:\Users\x\Downloads\0008-64bit_Win7_Win8_Win81_Win10_R281\WIN64\RCORES64.dat`,
		`C:\Users\x\Downloads\Install_Win10_10035_06242019\TOOL\RTInstaller64.dat`,
	} {
		if !pacoteDeDriverOuInstalador(caminho) {
			t.Errorf("%s e pacote de driver", caminho)
		}
	}
	if pacoteDeDriverOuInstalador(`C:\Users\x\Desktop\config.dat`) {
		t.Errorf("arquivo solto no Desktop nao e pacote de driver")
	}
}

func TestCaminhosDeDownloadComParentesesEEspacos(t *testing.T) {
	casos := map[string]string{
		`01/08/2026 20:32:50  C:\Users\SnyX\Downloads\Citizen Mssinha no Night - by Community Zenit Play.zip  <- https://www.mediafire.com/file/x/y.zip/file`: `C:\Users\SnyX\Downloads\Citizen Mssinha no Night - by Community Zenit Play.zip`,
		`09/09/2026 05:24:29  D:\Downloads Microsoft Edge\SOM PVP TEQUINHO ATUALIZADO - VIDEO (1).rar  <- https://drive.google.com/x`:                         `D:\Downloads Microsoft Edge\SOM PVP TEQUINHO ATUALIZADO - VIDEO (1).rar`,
		`09/09/2026 09:23:54  D:\Downloads Microsoft Edge\AnyDesk (1).exe  <- https://anydesk.com/`:                                                           `D:\Downloads Microsoft Edge\AnyDesk (1).exe`,
		`C:\Users\dom\Downloads\loader_v2.rar  (deletado em 03/05/2025 19:02:17)`:                                                                             `C:\Users\dom\Downloads\loader_v2.rar`,
		`D:\GTAV\dinput8.dll  (412 KB, 09/09/2026)`:                                                                                                           `D:\GTAV\dinput8.dll`,
	}
	for texto, esperado := range casos {
		got := caminhosNoTexto(texto)
		if len(got) != 1 || got[0] != esperado {
			t.Errorf("texto %q\n  esperava %q\n  veio     %v", resumeTexto(texto, 60), esperado, got)
		}
	}
}

func criaZip(t *testing.T, caminho string, arquivos map[string]string) {
	t.Helper()
	f, err := os.Create(caminho)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z := zip.NewWriter(f)
	for nome, conteudo := range arquivos {
		w, err := z.Create(nome)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(conteudo))
	}
	z.Close()
}

func TestConteudoDePacoteCompactado(t *testing.T) {
	a := assinaturasDeTeste(t)
	dir := t.TempDir()

	limpo := filepath.Join(dir, "mod visual.zip")
	criaZip(t, limpo, map[string]string{"textures/carro.ytd": "x", "leiame.txt": "instrucoes"})
	f, _ := os.Open(limpo)
	info, _ := f.Stat()
	itens, _, err := lerZip(f, info.Size(), 100)
	f.Close()
	if err != nil || len(itens) != 2 {
		t.Fatalf("esperava 2 itens, veio %d (%v)", len(itens), err)
	}
	if s := avaliarPacote(PacoteAnalisado{Caminho: limpo, Itens: itens}, a); sinaisTem(s, Critico, "mod visual") || sinaisTem(s, Alerta, "mod visual") {
		t.Errorf("mod visual limpo nao devia acusar: %+v", s)
	}

	comCheat := PacoteAnalisado{Caminho: `C:\Users\x\Downloads\citizen com agua.zip`, Itens: []ItemDePacote{
		{Nome: "citizen-scripting-lua.dll", Tamanho: 2 * 1024 * 1024},
		{Nome: "leiame.txt", Tamanho: 500},
	}}
	s := avaliarPacote(comCheat, a)
	if !sinaisTem(s, Critico, "programa(s)/script(s) dentro") {
		t.Errorf("dll dentro de pacote do jogo devia ser critico: %+v", s)
	}

	comNomeDeCheat := PacoteAnalisado{Caminho: `C:\Users\x\Downloads\pack.zip`, Itens: []ItemDePacote{
		{Nome: "eulen_loader.exe", Tamanho: 3 * 1024 * 1024},
	}}
	if s := avaliarPacote(comNomeDeCheat, a); !sinaisTem(s, Critico, "nome de cheat") {
		t.Errorf("cheat dentro do zip devia ser critico: %+v", s)
	}
}

func TestNomesDentroDoRarPorTexto(t *testing.T) {
	dados := append([]byte("Rar!\x1a\x07\x01\x00"), []byte("\x00\x00menu\\eulen.dll\x00\x00\x05config legit.txt\x00\x01\x02")...)
	itens := nomesDentroDoRarPorTexto(dados, 50)
	achou := map[string]bool{}
	for _, i := range itens {
		achou[i.Nome] = true
	}
	if !achou[`menu\eulen.dll`] {
		t.Errorf("devia extrair menu\\eulen.dll dos nomes do rar: %+v", itens)
	}
	if !achou["config legit.txt"] {
		t.Errorf("devia extrair config legit.txt: %+v", itens)
	}
}

func TestEhPacote(t *testing.T) {
	casos := map[string]string{"a.zip": "zip", "b.RAR": "rar", "c.7z": "7z", "d.exe": "", `C:\x\y.rar`: "rar"}
	for nome, esperado := range casos {
		if got := ehPacote(nome); got != esperado {
			t.Errorf("%s: esperava %q, veio %q", nome, esperado, got)
		}
	}
}

func TestCaminhoNaoPegaParenteseSolto(t *testing.T) {
	if got := caminhosNoTexto(`Executaveis/arquivos compactados na lixeira de jogador (C:\)`); len(got) != 0 {
		t.Errorf("(C:\\) no titulo nao e caminho de arquivo: %v", got)
	}
	got := caminhosNoTexto(`08/09/2026 12:52:58  C:\Users\jogador\Downloads\loader_v2.rar`)
	if len(got) != 1 || got[0] != `C:\Users\jogador\Downloads\loader_v2.rar` {
		t.Errorf("esperava o rar, veio %v", got)
	}
	comParenteses := caminhosNoTexto(`D:\Downloads\AnyDesk (1).exe  <- https://anydesk.com/`)
	if len(comParenteses) != 1 || comParenteses[0] != `D:\Downloads\AnyDesk (1).exe` {
		t.Errorf("parenteses do nome devem ser mantidos: %v", comParenteses)
	}
	titulo := caminhosNoTexto(`Executaveis compactados na lixeira (C:\)`, `C:\Users\x\Downloads\a.rar`)
	if len(titulo) != 1 || titulo[0] != `C:\Users\x\Downloads\a.rar` {
		t.Errorf("so o caminho de verdade deve sobrar: %v", titulo)
	}
}

func TestPacoteInstaladorComumNaoAcusa(t *testing.T) {
	a := assinaturasDeTeste(t)
	instalador := PacoteAnalisado{Caminho: `C:\Users\x\Downloads\vibranceGUI.zip`, Itens: []ItemDePacote{
		{Nome: "vibranceGUI.exe", Tamanho: 776 * 1024},
		{Nome: "leiame.txt", Tamanho: 2000},
	}}
	for _, s := range avaliarPacote(instalador, a) {
		if s.Severidade != Info {
			t.Errorf("instalador comum nao devia acusar: %+v", s)
		}
	}
}

func TestPacoteCitizenOficialVsAdulterado(t *testing.T) {
	a := assinaturasDeTeste(t)
	oficiais := []ItemDePacote{}
	for _, nome := range []string{
		`citizen\clr2\lib\mono\4.5\CitizenFX.Core.dll`, `citizen\clr2\lib\mono\4.5\Mono.CSharp.dll`,
		`citizen\clr2\lib\mono\4.5\System.Core.dll`, `citizen\clr2\lib\mono\4.5\MsgPack.dll`,
		`citizen\scripting\v8\citizen-scripting-v8.dll`,
	} {
		oficiais = append(oficiais, ItemDePacote{Nome: nome, Tamanho: 1024 * 100})
	}
	s := avaliarPacote(PacoteAnalisado{Caminho: `C:\Users\x\Downloads\citizen sem gargalo.rar`, Itens: oficiais}, a)
	if sinaisTem(s, Critico, "programa(s)/script(s) dentro") {
		t.Errorf("pacote com a estrutura oficial do citizen devia ser alerta, nao critico: %+v", s)
	}
	if !sinaisTem(s, Alerta, "otimizacao de FPS") {
		t.Errorf("devia explicar que parece pacote de otimizacao: %+v", s)
	}

	adulterado := append(append([]ItemDePacote{}, oficiais...), ItemDePacote{Nome: `citizen\bypass.dll`, Tamanho: 500 * 1024})
	s = avaliarPacote(PacoteAnalisado{Caminho: `C:\Users\x\Downloads\citizen.rar`, Itens: adulterado}, a)
	if !sinaisTem(s, Critico, "nao pertencem a ela") {
		t.Errorf("arquivo estranho dentro do citizen devia ser critico: %+v", s)
	}
}

func TestConfigDoJogoNaoEhPacoteModificado(t *testing.T) {
	for _, nome := range []string{"gta5_settings.xml", "settings.cfg", "config.ini", "server.json"} {
		if arquivoDoUniversoDoJogo(nome) != "" {
			t.Errorf("%s e arquivo de configuracao, nao pacote do jogo", nome)
		}
	}
	if arquivoDoUniversoDoJogo("citizen.rar") == "" {
		t.Errorf("citizen.rar continua sendo pacote do jogo")
	}
}

func TestDependenciasDoFiveMSemAssinatura(t *testing.T) {
	a := assinaturasDeTeste(t)
	arquivos := []ArquivoDoJogo{
		{Nome: "FiveM.exe", Caminho: `C:\FiveM.app\FiveM.exe`, Assinatura: "Valid", Assinante: "CN=the CitizenFX Collective", NaRaiz: true},
		{Nome: "CoreRT.dll", Caminho: `C:\FiveM.app\CoreRT.dll`, Assinatura: "Valid", Assinante: "CN=the CitizenFX Collective", NaRaiz: true},
		{Nome: "libuv.dll", Caminho: `C:\FiveM.app\libuv.dll`, Assinatura: "NotSigned", NaRaiz: true},
		{Nome: "v8-9.3.345.16.dll", Caminho: `C:\FiveM.app\v8-9.3.345.16.dll`, Assinatura: "NotSigned", NaRaiz: true},
		{Nome: "hook.dll", Caminho: `C:\FiveM.app\hook.dll`, Assinatura: "NotSigned", NaRaiz: true},
	}
	s := avaliarIntegridadeDoJogo(`C:\FiveM.app`, arquivos, a)
	for _, dep := range []string{"libuv", "v8-9"} {
		if sinaisTem(s, Alerta, dep) || sinaisTem(s, Critico, dep) {
			t.Errorf("%s e dependencia conhecida do FiveM sem assinatura: %+v", dep, s)
		}
	}
	if !sinaisTem(s, Alerta, "hook.dll") {
		t.Errorf("dll desconhecida sem assinatura devia continuar sendo alerta: %+v", s)
	}
}

func TestSessaoETWDeRotinaEBinarioDoDefender(t *testing.T) {
	for _, nome := range []string{"defenderapiloggerlowpriv", "diagtrack-listener", "perfdiag logger", "ruximlog"} {
		if !sessaoDeRotina(nome) {
			t.Errorf("%s e sessao de rotina do Windows", nome)
		}
	}
	if sessaoDeRotina("eventlog-security") {
		t.Errorf("eventlog-security nao e rotina descartavel")
	}
	a := assinaturasDeTeste(t)
	eventos := []EventoETW{
		{ID: 3004, Hora: time.Now(), Dados: map[string]string{"FileNameBuffer": `\Device\HarddiskVolume2\ProgramData\Microsoft\Windows Defender\Platform\4.18\DefenderSessionHelper.exe`}},
		{ID: 3033, Hora: time.Now(), Dados: map[string]string{"FileNameBuffer": `\Device\HarddiskVolume2\Users\x\AppData\Local\Temp\drv.sys`}},
	}
	s := avaliarEventosDeIntegridade(eventos, a)
	if sinaisTem(s, Critico, "DefenderSessionHelper") || sinaisTem(s, Alerta, "DefenderSessionHelper") {
		t.Errorf("binario do proprio Defender nao devia acusar: %+v", s)
	}
	if !sinaisTem(s, Critico, "drv.sys") {
		t.Errorf("driver em Temp continua critico: %+v", s)
	}
}

func TestDriverDeAnticheatEArquivoDeTexto(t *testing.T) {
	if !driverDeAnticheatConhecido("vgk.sys") {
		t.Errorf("vgk.sys e o driver do Vanguard")
	}
	if driverDeAnticheatConhecido("iqvw64e.sys") {
		t.Errorf("iqvw64e nao e anticheat")
	}
	if !extensaoDeTexto("autohotkey.vim") {
		t.Errorf(".vim e arquivo de texto, nao macro")
	}
	if extensaoDeTexto("autohotkey.exe") {
		t.Errorf(".exe nao e texto")
	}
}

func TestListagemDePacoteComTamanho(t *testing.T) {
	saida7z := `Path = citizen\clr2\CitizenFX.Core.dll
Size = 262144
Modified = 2026-07-16 01:35:21

Path = citizen\bypass.dll
Size = 512000
Modified = 2026-07-16 01:35:22
`
	itens := lerListagemDePacote(saida7z, false, 100)
	if len(itens) != 2 {
		t.Fatalf("esperava 2 itens do 7z, veio %d: %+v", len(itens), itens)
	}
	if itens[0].Tamanho != 262144 {
		t.Errorf("tamanho do primeiro item errado: %d", itens[0].Tamanho)
	}

	saidaUnrar := `
 Attributes      Size     Date    Time   Name
----------- ---------  ---------- -----  ----
    ..A....    262144  2026-07-16 01:35  citizen\clr2\CitizenFX.Core.dll
    ..A....       512  2026-07-16 01:35  leiame.txt
----------- ---------  ---------- -----  ----
`
	itens = lerListagemDePacote(saidaUnrar, true, 100)
	if len(itens) != 2 {
		t.Fatalf("esperava 2 itens do unrar, veio %d: %+v", len(itens), itens)
	}
	if itens[0].Nome != `citizen\clr2\CitizenFX.Core.dll` || itens[0].Tamanho != 262144 {
		t.Errorf("item do unrar errado: %+v", itens[0])
	}
	if formataTamanho(0) != "tamanho nao informado" {
		t.Errorf("tamanho zero deve ser explicito, nao '0 KB'")
	}
	if formataTamanho(262144) != "256 KB" {
		t.Errorf("formatacao errada: %s", formataTamanho(262144))
	}
	if formataTamanho(5*1024*1024) != "5.0 MB" {
		t.Errorf("formatacao errada: %s", formataTamanho(5*1024*1024))
	}
}

func TestLimiteZeroSignificaSemLimite(t *testing.T) {
	inicio := time.Now().Add(-10 * time.Hour)
	if estourouOTempo(inicio, 0) {
		t.Errorf("limite 0 tem que significar sem limite, mesmo depois de 10 horas")
	}
	if !estourouOTempo(inicio, time.Minute) {
		t.Errorf("limite de 1 minuto ja estourou depois de 10 horas")
	}
	if estourouOTamanho(999*1024*1024*1024, 0) {
		t.Errorf("limite de tamanho 0 tem que significar sem limite")
	}
	if !estourouOTamanho(2*1024, 1024) {
		t.Errorf("2 KB estoura limite de 1 KB")
	}
	if descreveLimite(0) != "sem limite de tempo" {
		t.Errorf("descricao errada: %s", descreveLimite(0))
	}
}

func TestVarreduraDeConteudoSemLimiteLeTudo(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "Downloads"), 0o755)
	for i := 0; i < 60; i++ {
		os.WriteFile(filepath.Join(dir, "Downloads", fmt.Sprintf("arq%02d.txt", i)), []byte("conteudo comum"), 0o644)
	}
	os.WriteFile(filepath.Join(dir, "Downloads", "zzz_ultimo.lua"), []byte("-- dumped with eulen"), 0o644)

	res := varrerConteudo(assinaturasDeTeste(t), []string{dir}, 0, 0, nil)
	if res.Interrompido {
		t.Errorf("com limite 0 a varredura nao pode ser interrompida")
	}
	if res.Arquivos < 61 {
		t.Errorf("esperava ler os 61 arquivos, leu %d", res.Arquivos)
	}
	achou := false
	for _, a := range res.Achados {
		if strings.Contains(a.Caminho, "zzz_ultimo.lua") {
			achou = true
		}
	}
	if !achou {
		t.Errorf("o arquivo do fim da lista tem que ser analisado tambem")
	}
}

func TestStoppedSozinhoNaoAcusa(t *testing.T) {
	a := assinaturasDeTeste(t)
	for _, texto := range []string{
		"O servico foi stopped com sucesso",
		"Process stopped by user",
		"service stopped",
		"stopped",
	} {
		if classe, termo := a.Classificar(texto); classe != SemMatch {
			t.Errorf("%q e frase comum de log, nao pode casar (casou com %q)", texto, termo)
		}
	}
	for _, texto := range []string{"stopped menu", "stoppedcheats.exe", "stopped_cheat_v3.rar", "discord.gg/stoppedmenu"} {
		if classe, _ := a.Classificar(texto); classe == SemMatch {
			t.Errorf("%q devia casar como cheat", texto)
		}
	}
}

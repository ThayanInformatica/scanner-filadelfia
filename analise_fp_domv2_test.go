package main

import (
	"strings"
	"testing"
)

func TestUniversoDoJogoNaoCasaSubstring(t *testing.T) {
	for _, nome := range []string{"se  vc tem coragem.html", "basico.exe", "morph.rar", "vegetal.zip", "storage.exe", "garagem.rar"} {
		if m := arquivoDoUniversoDoJogo(nome); m != "" {
			t.Errorf("%q nao e arquivo do jogo, casou %q", nome, m)
		}
	}
	for nome, esperado := range map[string]string{"gg.andrefivem (2).rar": "fivem", "citizen_boost.rar": "citizen", "QuantV.asi": "asi", "gta5_settings.zip": "gta5", "ragemp_pack.rar": "ragemp", "GTAV mods.zip": "gtav"} {
		if m := arquivoDoUniversoDoJogo(nome); m != esperado {
			t.Errorf("%q devia casar %q, veio %q", nome, esperado, m)
		}
	}
}

func TestPacoteCitizenComScriptingOficialEhAlerta(t *testing.T) {
	a := assinaturasDeTeste(t)
	var itens []ItemDePacote
	for _, n := range []string{
		`citizen\clr2\lib\mono\4.5\CitizenFX.Core.dll`, `citizen\clr2\lib\mono\4.5\v2\CitizenFX.FiveM.dll`,
		`citizen\clr2\lib\mono\4.5\System.Core.dll`, `citizen\scripting\lua\json.lua`, `citizen\scripting\v8\main.js`,
		`citizen\shaderz\makeshader.cmd`, `citizen\scripting\resource_init.lua`,
	} {
		itens = append(itens, ItemDePacote{Nome: n, Tamanho: 1000})
	}
	sinais := avaliarPacote(PacoteAnalisado{Caminho: `C:\Users\x\Downloads\citizen.rar`, Formato: "rar", Itens: itens}, a)
	for _, s := range sinais {
		if s.Severidade == Critico {
			t.Fatalf("pasta citizen oficial com scripting e shaderz nao pode ser critico: %s", s.Titulo)
		}
	}
	if len(sinais) == 0 || !strings.Contains(sinais[0].Detalhe, "citizen") {
		t.Fatalf("esperava alerta explicando a pasta citizen: %+v", sinais)
	}
}

func TestPacoteQuantVEhModGrafico(t *testing.T) {
	a := assinaturasDeTeste(t)
	itens := []ItemDePacote{
		{Nome: "Part2/NUI in-process GPU on (default)/FiveM.app/plugins/dxgi.dll", Tamanho: 4700000},
		{Nome: "QV_Optionals/Trainer/FiveM.app/plugins/QuantV.asi", Tamanho: 2100000},
		{Nome: "Part1/citizen/common/data/timecycle/qv.xml", Tamanho: 100},
	}
	sinais := avaliarPacote(PacoteAnalisado{Caminho: `C:\Users\x\Downloads\QuantV FiveM 2025-6-12.zip`, Formato: "zip", Itens: itens}, a)
	if len(sinais) != 1 || sinais[0].Severidade != Alerta || !strings.Contains(sinais[0].Titulo, "mod grafico") {
		t.Fatalf("QuantV tem que virar alerta de mod grafico: %+v", sinais)
	}
	itens = append(itens, ItemDePacote{Nome: "QV_Optionals/loader.exe", Tamanho: 5000})
	sinais = avaliarPacote(PacoteAnalisado{Caminho: `C:\Users\x\Downloads\QuantV FiveM 2025-6-12.zip`, Formato: "zip", Itens: itens}, a)
	if len(sinais) == 0 || sinais[0].Severidade != Critico {
		t.Fatalf("mod grafico com exe estranho dentro continua critico: %+v", sinais)
	}
}

func TestPacoteSoComFxmanifestEhRecurso(t *testing.T) {
	a := assinaturasDeTeste(t)
	itens := []ItemDePacote{{Nome: `trafficprops/fxmanifest.lua`, Tamanho: 449}, {Nome: `trafficprops/stream/prop.ytd`, Tamanho: 90000}}
	sinais := avaliarPacote(PacoteAnalisado{Caminho: `C:\Users\x\Downloads\trafficprops.zip`, Formato: "zip", Itens: itens}, a)
	if len(sinais) != 1 || sinais[0].Severidade != Info || !strings.Contains(sinais[0].Titulo, "recurso de servidor") {
		t.Fatalf("pacote so com fxmanifest e recurso, nao programa: %+v", sinais)
	}
}

func TestRecursoDeServidorEContextoDeRelatorio(t *testing.T) {
	existe := func(c string) bool {
		return strings.EqualFold(c, `D:\Freela\Filadelfia\resources\[scripts]\death-stats\fxmanifest.lua`)
	}
	if !recursoDeServidorFiveM(`D:\Freela\Filadelfia\resources\[scripts]\death-stats\server\suspicion.lua`, existe) {
		t.Fatal("script dentro de recurso com fxmanifest tinha que ser reconhecido")
	}
	if recursoDeServidorFiveM(`C:\Users\x\Downloads\eulen.lua`, existe) {
		t.Fatal("lua solto em Downloads nao e recurso")
	}
	for _, txt := range []string{
		`"titulo": "Executado (RecentDocs) bate com assinatura 'config legit'"`,
		"[OK] Nenhuma placa DMA/FPGA nem dispositivo de aim assist (KMBox, MAKCU)",
		"Drivers mapeados manualmente (kdmapper) nao aparecem nesta lista",
	} {
		if !contextoDeRelatorioDoScanner(txt) {
			t.Errorf("trecho de relatorio nao reconhecido: %q", txt)
		}
	}
	if contextoDeRelatorioDoScanner("mano baixa o eulen ai discord.gg/xyz") {
		t.Fatal("conversa normal nao e relatorio")
	}
	if !arquivoDeRelatorioDoScanner(`C:\Users\x\Downloads\scanner-Dom-PC-20260909-164427.json`) || arquivoDeRelatorioDoScanner(`scanner_eulen.exe`) || arquivoDeRelatorioDoScanner(`scannerx.lua`) {
		t.Fatal("so o arquivo de relatorio do scanner e ignorado, nao qualquer 'scanner'")
	}
}

func TestPontoDePartidaUSNRespeitaPrimeiroUSN(t *testing.T) {
	saida := "Usn Journal ID   : 0x01dc8a2b\nFirst Usn        : 0x0000000010000000\nNext Usn         : 0x0000000012000000\n"
	if v := pontoDePartidaUSN(saida, 400*1024*1024); v != 0x10000000 {
		t.Fatalf("janela maior que o journal tem que cair no primeiro USN, veio %#x", v)
	}
	if v := pontoDePartidaUSN(saida, 0x100000); v != 0x12000000-0x100000 {
		t.Fatalf("janela pequena tem que ficar proxima ao fim, veio %#x", v)
	}
	ptbr := "ID do diario USN : 0x01dc8a2b\nPrimeiro USN     : 0x1000\nProximo USN      : 0x9000\n"
	if v := pontoDePartidaUSN(ptbr, 0x10); v != 0x9000-0x10 {
		t.Fatalf("rotulo em portugues, veio %#x", v)
	}
}

func TestLerUSNCsvIgnoraLinhasDeErro(t *testing.T) {
	texto := "Error: The specified USN is invalid.\nTry again\n\"File name\",\"Reason\",\"Time stamp\"\n\"eulen_loader.exe\",\"0x80000200\",\"1/2/2026 15:04:05\"\n"
	eventos, total, err := lerUSNCsv(strings.NewReader(texto), 1000, func(string) bool { return true })
	if err != nil || total != 1 || len(eventos) != 1 {
		t.Fatalf("linhas de erro nao contam como registro: total=%d eventos=%d err=%v", total, len(eventos), err)
	}
}

func TestSelfDestructENomesDoKitNaoAcusam(t *testing.T) {
	a := assinaturasDeTeste(t)
	for _, texto := range []string{
		"if (!$NonDestructive) { # Self destruct! Remove-Item function:deactivate }",
		"# Self destruct! unset -f deactivate",
	} {
		if classe, termo := a.Classificar(texto); classe != SemMatch {
			t.Errorf("script de virtualenv nao pode casar (casou com %q): %q", termo, texto)
		}
	}
	for _, termo := range a.TermosParaConteudo() {
		if strings.EqualFold(termo, "self destruct") || strings.EqualFold(termo, "selfdestruct") {
			t.Errorf("%q nao pode estar na busca de conteudo: aparece em todo activate.ps1 do Python", termo)
		}
	}
}

func TestRelatorioColadoNoDiscordEhReconhecido(t *testing.T) {
	for _, trecho := range []string{
		"Sobrevive a limpador de rastro e a exclusao do arquivo [OK] Nenhum programa com nome ou hash de cheat",
		"RTCore64.sys Drivers dessa lista sao abusados por kdmapper e afins para injetar cheat no kernel",
		"PC POSSIVELMENTE 'STOPADO': 3 registro(s) de execucao desligados",
		"Duracao da analise: 20m19s",
		"10 dll(s) do Windows conferidas contra o arquivo em disco",
	} {
		if !contextoDeRelatorioDoScanner(trecho) {
			t.Errorf("trecho de relatorio nao reconhecido: %q", trecho)
		}
	}
	if contextoDeRelatorioDoScanner("mano me passa o eulen ai, discord.gg/xyz") {
		t.Error("conversa de verdade nao pode ser confundida com relatorio")
	}
}

func TestProcessoDeSistemaForaDaVarreduraDeMemoria(t *testing.T) {
	casos := []struct {
		caminho, assinante string
		fora               bool
	}{
		{`C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe`, "", true},
		{`C:\Windows\System32\svchost.exe`, "", true},
		{`C:\Program Files (x86)\Steam\Steam.exe`, "CN=Valve Corp.", true},
		{`C:\Program Files\obs-studio\bin\64bit\obs64.exe`, "CN=Hugh Bailey", false},
		{`C:\Users\Dom\AppData\Roaming\xk9.exe`, "", false},
	}
	for _, c := range casos {
		nome := c.caminho[strings.LastIndex(c.caminho, `\`)+1:]
		if got := processoForaDaVarreduraDeMemoria(nome, c.caminho, c.assinante); got != c.fora {
			t.Errorf("%s: fora=%v, esperado %v", nome, got, c.fora)
		}
	}
}

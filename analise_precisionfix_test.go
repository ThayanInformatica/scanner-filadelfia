package main

import (
	"strings"
	"testing"
	"time"
)

func TestLerPCANosDoisFormatos(t *testing.T) {
	dic := `C:\Users\Nardo\Desktop\precision v3.exe|2026-09-08 21:39:11.799
C:\Program Files\WinRAR\WinRAR.exe|2026-09-09 10:21:06.000
linha invalida sem barra
`
	e := lerPCA(dic, "PcaAppLaunchDic.txt")
	if len(e) != 2 {
		t.Fatalf("esperava 2 execucoes, veio %d: %+v", len(e), e)
	}
	if e[0].Caminho != `C:\Users\Nardo\Desktop\precision v3.exe` || e[0].Hora.IsZero() {
		t.Fatalf("primeira linha errada: %+v", e[0])
	}

	geral := `2026-09-09 22:53:36|Run|C:\Users\Nardo\AppData\Local\FiveM\FiveM.exe|FiveM|CitizenFX|1.0`
	e = lerPCA(geral, "PcaGeneralDb0.txt")
	if len(e) != 1 || !strings.HasSuffix(e[0].Caminho, `FiveM.exe`) || e[0].Hora.IsZero() {
		t.Fatalf("formato GeneralDb nao foi lido: %+v", e)
	}
}

func TestAvaliarPCAAcusaNomeDeCheat(t *testing.T) {
	a := assinaturasDeTeste(t)
	agora := time.Date(2026, 9, 10, 10, 0, 0, 0, time.Local)
	e := []ExecucaoPCA{
		{Caminho: `C:\Users\x\Downloads\eulen.exe`, Hora: agora.Add(-2 * time.Hour), Fonte: "PcaAppLaunchDic.txt"},
		{Caminho: `C:\Program Files\WinRAR\WinRAR.exe`, Hora: agora.Add(-3 * time.Hour), Fonte: "PcaAppLaunchDic.txt"},
	}
	s := avaliarPCA(e, a, agora)
	if !sinaisTem(s, Critico, "PCA bate com assinatura") {
		t.Fatalf("nome de cheat no PCA e critico: %+v", s)
	}
	if !sinaisTem(s, Info, "ultimos 7 dias") {
		t.Fatalf("os recentes viram informativo: %+v", s)
	}
	if avaliarPCA(nil, a, agora) != nil {
		t.Fatal("sem execucao, sem sinal")
	}
}

func TestLerZoneIdentifier(t *testing.T) {
	conteudo := "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://discord.com/channels/1\r\nHostUrl=https://cdn.discordapp.com/attachments/1/2/precisionfix.zip\r\n"
	host, ref, zona := lerZoneIdentifier(conteudo)
	if host != "https://cdn.discordapp.com/attachments/1/2/precisionfix.zip" {
		t.Fatalf("host errado: %q", host)
	}
	if ref != "https://discord.com/channels/1" || zona != "3" {
		t.Fatalf("referencia ou zona errada: %q %q", ref, zona)
	}
	if h, _, _ := lerZoneIdentifier("lixo sem igual"); h != "" {
		t.Fatalf("conteudo invalido nao produz host: %q", h)
	}
}

func TestOrigemDeDownloadPorSeveridade(t *testing.T) {
	a := assinaturasDeTeste(t)
	origens := []OrigemDeDownload{
		{Arquivo: `C:\Users\x\Downloads\loader.exe`, Host: "https://eulen.cc/download/loader.exe"},
		{Arquivo: `C:\Users\x\Downloads\pacote.zip`, Host: "https://cdn.discordapp.com/attachments/1/2/pacote.zip"},
		{Arquivo: `C:\Users\x\Downloads\FiveM.exe`, Host: "https://fivem.net/download"},
	}
	s := avaliarOrigemDeDownload(origens, a)
	if !sinaisTem(s, Critico, "bate com") {
		t.Fatalf("dominio de cheat no Zone.Identifier e critico: %+v", s)
	}
	if !sinaisTem(s, Alerta, "site de compartilhamento") {
		t.Fatalf("discord cdn vira alerta: %+v", s)
	}
	if !sinaisTem(s, Info, "Origem gravada dentro de") {
		t.Fatalf("download normal vira informativo: %+v", s)
	}
	if avaliarOrigemDeDownload(nil, a) != nil {
		t.Fatal("sem origem, sem sinal")
	}
}

func servicoDeTeste(nome string, minuto int, desativado bool) ServicoConferido {
	return ServicoConferido{
		Nome: nome, Descricao: "registro de execucao", Desativado: desativado,
		Alterado: time.Date(2026, 9, 8, 22, minuto, 0, 0, time.Local),
	}
}

func TestServicosDesligadosEmLote(t *testing.T) {
	lote := []ServicoConferido{
		servicoDeTeste("DiagTrack", 10, true),
		servicoDeTeste("DPS", 10, true),
		servicoDeTeste("PcaSvc", 11, true),
		servicoDeTeste("SysMain", 11, true),
	}
	s := avaliarAlteracaoEmLoteDeServicos(lote)
	if len(s) != 1 || s[0].Severidade != Alerta || !strings.Contains(s[0].Titulo, "4 servicos") {
		t.Fatalf("quatro servicos no mesmo minuto e lote: %+v", s)
	}
	if !strings.Contains(s[0].Detalhe, "nao prova ma intencao sozinho") {
		t.Fatalf("tem que trazer a ressalva do otimizador popular: %s", s[0].Detalhe)
	}
}

func TestServicosAlteradosEmDiasDiferentesNaoSaoLote(t *testing.T) {
	var espalhado []ServicoConferido
	for i, nome := range []string{"DiagTrack", "DPS", "PcaSvc", "SysMain"} {
		s := servicoDeTeste(nome, 0, true)
		s.Alterado = s.Alterado.AddDate(0, 0, -i*3)
		espalhado = append(espalhado, s)
	}
	if s := avaliarAlteracaoEmLoteDeServicos(espalhado); s != nil {
		t.Fatalf("alterados com dias de diferenca nao e lote: %+v", s)
	}
}

func TestServicosLigadosNaoViramSinal(t *testing.T) {
	var ligados []ServicoConferido
	for _, nome := range []string{"DiagTrack", "DPS", "PcaSvc", "SysMain"} {
		ligados = append(ligados, servicoDeTeste(nome, 10, false))
	}
	if s := avaliarAlteracaoEmLoteDeServicos(ligados); s != nil {
		t.Fatalf("servicos todos ligados nao acusam nada: %+v", s)
	}
	if s := avaliarAlteracaoEmLoteDeServicos(ligados[:2]); s != nil {
		t.Fatalf("menos de tres nao forma lote: %+v", s)
	}
}

func TestDriverDeUtilitarioNaoEhCritico(t *testing.T) {
	sev, nota := severidadeDeDriverInstalado(`C:\Program Files (x86)\MSI Afterburner\RTCore64.sys`)
	if sev != Alerta || !strings.Contains(nota, "utilitarios de hardware") {
		t.Fatalf("driver na pasta do proprio utilitario e alerta: %v %s", sev, nota)
	}
	sev, nota = severidadeDeDriverInstalado(`C:\Users\camar\AppData\Local\Temp\iqvw64e.sys`)
	if sev != Critico || !strings.Contains(nota, "kdmapper") {
		t.Fatalf("driver largado no Temp continua critico: %v %s", sev, nota)
	}
}

func TestHashDeDriverVulneravelSegueOCaminho(t *testing.T) {
	sev, _, coberto := severidadeDeHashDeDriver("driver vulneravel BYOVD (LOLDrivers): rtcore64.sys", `C:\Program Files (x86)\MSI Afterburner\RTCore64.sys`)
	if sev != Alerta || !coberto {
		t.Fatalf("BYOVD no Program Files e alerta e ja coberto pelo nome: %v %v", sev, coberto)
	}
	sev, _, coberto = severidadeDeHashDeDriver("driver vulneravel BYOVD (LOLDrivers): rtcore64.sys", `D:\citzen\RTCore64.sys`)
	if sev != Critico || coberto {
		t.Fatalf("mesmo driver fora do sistema continua critico: %v %v", sev, coberto)
	}
	sev, _, _ = severidadeDeHashDeDriver("loader do eulen v3", `C:\Program Files\x\y.exe`)
	if sev != Critico {
		t.Fatalf("hash de cheat de verdade e critico em qualquer pasta: %v", sev)
	}
}

func TestInstalacaoDeDriverAgrupaRepeticao(t *testing.T) {
	d := &InstalacaoDeDriver{Nome: "rtcore64.sys", Imagem: `C:\Program Files (x86)\MSI Afterburner\RTCore64.sys`, Tipo: "kernel mode driver", Vezes: 30,
		Primeira: time.Date(2026, 8, 12, 9, 0, 0, 0, time.Local), Ultima: time.Date(2026, 9, 10, 18, 51, 20, 0, time.Local)}
	texto := d.Descrever()
	if !strings.Contains(texto, "Registrado 30 vezes") || !strings.Contains(texto, "sobe a cada boot") {
		t.Fatalf("tem que agrupar as repeticoes numa linha so: %s", texto)
	}
	unico := &InstalacaoDeDriver{Nome: "x.sys", Imagem: `C:\x.sys`, Tipo: "kernel", Vezes: 1, Ultima: time.Date(2026, 9, 1, 10, 0, 0, 0, time.Local)}
	if strings.Contains(unico.Descrever(), "Registrado") {
		t.Fatalf("uma vez so nao ganha contagem: %s", unico.Descrever())
	}
}

func TestConferenciaAoVivoSemJogoAberto(t *testing.T) {
	s := avaliarConferenciaAoVivo(ConferidoAoVivo{})
	if len(s) != 1 || s[0].Severidade != Alerta || !strings.Contains(s[0].Titulo, "NAO valem") {
		t.Fatalf("sem jogo aberto tem que avisar que o relatorio nao inocenta: %+v", s)
	}
	if !strings.Contains(s[0].Detalhe, "deixe o cheat ligado") {
		t.Fatalf("tem que ensinar como refazer o teste: %s", s[0].Detalhe)
	}
}

func TestConferenciaAoVivoTudoLimpo(t *testing.T) {
	v := ConferidoAoVivo{
		JogoAberto: true, NomeDoJogo: "FiveM_b3258_GTAProcess.exe", PIDDoJogo: 8248, ProcessosListados: 223,
		ModulosDoJogo: 293, HandlesNoJogo: 8, JanelasAnalisadas: 302, DriversCarregados: 179,
		MBExecutavelLidos: 1, MBDadosLidos: 4097, ThreadsAnalisadas: 262, DLLsConferidas: 10,
		ProcessosVarridos: 24, MBOutrosLidos: 1780,
	}
	s := avaliarConferenciaAoVivo(v)
	if len(s) != 1 || s[0].Severidade != Info || !strings.Contains(s[0].Titulo, "nao acharam nada") {
		t.Fatalf("tudo conferido e nada achado e informativo: %+v", s)
	}
	if !strings.Contains(s[0].Detalhe, "PID 8248") || !strings.Contains(s[0].Detalhe, "4097 MB") {
		t.Fatalf("o resumo tem que mostrar o que foi medido: %s", s[0].Detalhe)
	}
	if strings.Contains(s[0].Detalhe, "Nao deu para conferir") {
		t.Fatalf("com tudo preenchido nao pode sobrar checagem sem rodar: %s", s[0].Detalhe)
	}
}

func TestConferenciaAoVivoComAchado(t *testing.T) {
	v := ConferidoAoVivo{
		JogoAberto: true, NomeDoJogo: "FiveM_b3258_GTAProcess.exe", PIDDoJogo: 8248,
		ModulosDoJogo: 293, ModulosDesconhecidos: 1, HandlesNoJogo: 9, HandlesComEscrita: 1,
		MBDadosLidos: 4097, AchadosNaMemoria: 2, ThreadsAnalisadas: 262, DLLsConferidas: 10,
		JanelasAnalisadas: 302, DriversCarregados: 179, ProcessosVarridos: 24,
	}
	s := avaliarConferenciaAoVivo(v)
	if len(s) != 1 || s[0].Severidade != Critico || !strings.Contains(s[0].Titulo, "4 achado(s)") {
		t.Fatalf("achado ao vivo e critico e conta o total: %+v", s)
	}
	if !strings.Contains(s[0].Detalhe, "ACHADO(S)") {
		t.Fatalf("tem que marcar qual checagem achou: %s", s[0].Detalhe)
	}
}

func TestExecutavelSePassandoPorOutroPrograma(t *testing.T) {
	falso := ExecutavelEmDisco{
		Caminho: `C:\Users\x\Downloads\ccleaner.exe`, Nome: "ccleaner.exe", Tamanho: 900 * 1024,
		Modificado: time.Date(2026, 9, 10, 22, 0, 0, 0, time.Local),
	}
	s := avaliarExecutaveisEmDisco([]ExecutavelEmDisco{falso})
	if !sinaisTem(s, Critico, "se passando por ccleaner.exe") {
		t.Fatalf("ccleaner sem assinatura da Piriform e critico: %+v", s)
	}

	verdadeiro := falso
	verdadeiro.Assinatura, verdadeiro.Assinante, verdadeiro.CompanyName = "Valid", "Piriform Software Ltd", "Piriform Software Ltd"
	if s := avaliarExecutaveisEmDisco([]ExecutavelEmDisco{verdadeiro}); sinaisTem(s, Critico, "se passando") {
		t.Fatalf("ccleaner de verdade nao pode ser acusado: %+v", s)
	}
}

func TestExecutavelComNomeInternoDiferente(t *testing.T) {
	a := ExecutavelEmDisco{
		Caminho: `C:\Users\x\Desktop\atualizador.exe`, Nome: "atualizador.exe", Tamanho: 4096 * 1024,
		Modificado:       time.Date(2026, 9, 10, 22, 0, 0, 0, time.Local),
		OriginalFilename: "eulen_loader.exe", ProductName: "Loader",
	}
	s := avaliarExecutaveisEmDisco([]ExecutavelEmDisco{a})
	if !sinaisTem(s, Alerta, "nome diferente do nome interno") {
		t.Fatalf("nome interno divergente vira alerta: %+v", s)
	}
	if !strings.Contains(s[0].Detalhe, "eulen_loader.exe") {
		t.Fatalf("tem que mostrar o nome interno: %s", s[0].Detalhe)
	}
}

func TestExecutavelSemIdentificacaoEhSoContexto(t *testing.T) {
	a := ExecutavelEmDisco{
		Caminho: `C:\Users\x\Downloads\setup.exe`, Nome: "setup.exe", Tamanho: 2048 * 1024,
		Modificado: time.Date(2026, 9, 10, 22, 0, 0, 0, time.Local),
	}
	s := avaliarExecutaveisEmDisco([]ExecutavelEmDisco{a})
	if len(s) != 1 || s[0].Severidade != Info {
		t.Fatalf("exe sem assinatura e so contexto, nao acusacao: %+v", s)
	}
	assinado := a
	assinado.Assinatura, assinado.CompanyName = "Valid", "Alguma Empresa"
	if s := avaliarExecutaveisEmDisco([]ExecutavelEmDisco{assinado}); s != nil {
		t.Fatalf("exe assinado nao gera nada: %+v", s)
	}
	if avaliarExecutaveisEmDisco(nil) != nil {
		t.Fatal("sem arquivo, sem sinal")
	}
}

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

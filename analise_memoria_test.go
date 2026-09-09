package main

import (
	"strings"
	"testing"
	"time"
)

func blocoPE(recheio string) []byte {
	dados := make([]byte, 1024)
	copy(dados, "MZ")
	dados[0x3c] = 0x80
	copy(dados[0x80:], []byte{'P', 'E', 0, 0})
	copy(dados[0x200:], recheio)
	return dados
}

func TestDetectaCabecalhoPE(t *testing.T) {
	if !temCabecalhoPE(blocoPE("")) {
		t.Errorf("devia achar cabecalho PE")
	}
	if temCabecalhoPE([]byte(strings.Repeat("dados normais de jogo ", 40))) {
		t.Errorf("nao devia achar PE em dados comuns")
	}
	if temCabecalhoPE(append([]byte("MZ"), make([]byte, 200)...)) {
		t.Errorf("MZ sem PE nao conta")
	}
}

func TestAnalisarRegiaoDeMemoria(t *testing.T) {
	a := assinaturasDeTeste(t)
	buscador := NovoBuscador(a.TermosParaConteudo())

	rx := RegiaoDeMemoria{Base: 0x7ff0000, Tamanho: 200 * 1024, Protecao: "RX", Tipo: "privada (sem arquivo)", Privada: true, Executavel: true}
	if res := analisarRegiao(rx, blocoPE(""), buscador); res == nil || !res.TemPE {
		t.Errorf("regiao privada com PE devia virar achado: %+v", res)
	}
	comString := analisarRegiao(rx, []byte("codigo qualquer ... Eulen Loader v3 ... mais codigo"), buscador)
	if comString == nil || len(comString.Termos) == 0 || comString.Termos[0] != "eulen" {
		t.Errorf("devia achar a string eulen: %+v", comString)
	}
	limpa := analisarRegiao(rx, []byte(strings.Repeat("jit do lua gerando codigo ", 50)), buscador)
	if limpa != nil {
		t.Errorf("regiao RX sem PE e sem string nao devia virar achado: %+v", limpa)
	}
	rwx := RegiaoDeMemoria{Base: 0x1000, Tamanho: 128 * 1024, Protecao: "RWX", Tipo: "privada (sem arquivo)", Privada: true, Executavel: true}
	if res := analisarRegiao(rwx, []byte(strings.Repeat("x", 4096)), buscador); res == nil {
		t.Errorf("regiao RWX devia virar achado mesmo sem PE")
	}
}

func TestAvaliarMemoriaDoJogo(t *testing.T) {
	rx := RegiaoDeMemoria{Base: 0x7ff0000, Tamanho: 300 * 1024, Protecao: "RX", Tipo: "privada (sem arquivo)", Privada: true, Executavel: true}
	rwx := RegiaoDeMemoria{Base: 0x2000000, Tamanho: 128 * 1024, Protecao: "RWX", Tipo: "privada (sem arquivo)", Privada: true, Executavel: true}
	achados := []AchadoDeMemoria{
		{Regiao: rx, TemPE: true},
		{Regiao: rx, Termos: []string{"eulen"}, Contexto: "Eulen Loader v3 auth"},
		{Regiao: rwx},
	}
	s := avaliarMemoriaDoJogo(achados, 40, "FiveM_GTAProcess.exe")
	if !sinaisTem(s, Critico, "manual map") {
		t.Errorf("PE em regiao privada devia virar critico de manual map: %+v", s)
	}
	if !sinaisTem(s, Critico, "String de cheat 'eulen' NA MEMORIA") {
		t.Errorf("string na memoria devia ser critico: %+v", s)
	}
	if !sinaisTem(s, Alerta, "RWX") {
		t.Errorf("RWX devia ser alerta: %+v", s)
	}
	if s := avaliarMemoriaDoJogo(nil, 30, "FiveM_GTAProcess.exe"); len(s) != 0 {
		t.Errorf("memoria limpa nao devia gerar sinal: %+v", s)
	}
}

func TestLinhaDoTempoDaSessao(t *testing.T) {
	a := assinaturasDeTeste(t)
	agora := time.Now()
	jogo := agora.Add(-2 * time.Hour)
	eventos := []EventoDeExecucao{
		{Caminho: `C:\Users\jogador\AppData\Local\Temp\eulen_loader.exe`, Quando: agora.Add(-90 * time.Minute), Fonte: "BAM"},
		{Caminho: `C:\Users\jogador\Downloads\obs-studio.exe`, Quando: agora.Add(-80 * time.Minute), Fonte: "Prefetch"},
		{Caminho: `C:\Windows\System32\notepad.exe`, Quando: agora.Add(-70 * time.Minute), Fonte: "BAM"},
		{Caminho: `C:\Users\jogador\Downloads\susano.exe`, Quando: agora.Add(-5 * 24 * time.Hour), Fonte: "ShimCache"},
	}
	s := avaliarLinhaDoTempo(jogo, agora, eventos, a)
	if !sinaisTem(s, Critico, "eulen_loader.exe") {
		t.Errorf("cheat rodado durante a sessao devia ser critico: %+v", s)
	}
	if sinaisTem(s, Critico, "susano.exe") {
		t.Errorf("cheat de 5 dias atras esta fora da sessao e nao entra aqui: %+v", s)
	}
	if !sinaisTem(s, Info, "obs-studio.exe") {
		t.Errorf("programa comum da sessao devia entrar como info: %+v", s)
	}
	if sinaisTem(s, Info, "notepad.exe") {
		t.Errorf("programa do Windows nao devia entrar na lista: %+v", s)
	}
	if s := avaliarLinhaDoTempo(time.Time{}, agora, eventos, a); len(s) != 0 {
		t.Errorf("sem jogo aberto nao ha linha do tempo: %+v", s)
	}
}

func TestGerenciadorDeTarefasAbertoAntes(t *testing.T) {
	agora := time.Now()
	s := avaliarFechamentoRecente(agora.Add(-3*time.Minute), agora, agora.Add(-10*time.Minute))
	if !sinaisTem(s, Critico, "fechou o cheat pelo Gerenciador") {
		t.Errorf("taskmgr aberto depois do cheat devia ser critico: %+v", s)
	}
	s = avaliarFechamentoRecente(agora.Add(-3*time.Minute), agora, time.Time{})
	if !sinaisTem(s, Info, "Gerenciador de Tarefas") {
		t.Errorf("taskmgr sozinho devia ser informativo: %+v", s)
	}
	if s := avaliarFechamentoRecente(agora.Add(-3*time.Hour), agora, time.Time{}); len(s) != 0 {
		t.Errorf("taskmgr de 3 horas atras nao interessa: %+v", s)
	}
	if s := avaliarFechamentoRecente(time.Time{}, agora, time.Time{}); len(s) != 0 {
		t.Errorf("sem taskmgr nao ha sinal: %+v", s)
	}
}

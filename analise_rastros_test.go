package main

import (
	"strings"
	"testing"
	"time"
)

func TestRastrosStopadoViraCritico(t *testing.T) {
	instalado := time.Now().Add(-200 * 24 * time.Hour)
	r := RastrosDeExecucao{
		PrefetchDesligadoNoRegistro: true, SysMainDesativado: true, PrefetchLido: true, PrefetchQuantidade: 0,
		BAMLido: true, BAMQuantidade: 3, AmcacheLido: true, AmcacheQuantidade: 1705, ShimCacheLido: true, ShimCacheQuantidade: 800,
		LimpezasDeOutrosLogs: 1,
	}
	s := avaliarRastrosDeExecucao(r, instalado, time.Now())
	if len(s) != 1 || s[0].Severidade != Critico || !strings.Contains(s[0].Titulo, "STOPADO") {
		t.Fatalf("Prefetch desligado, vazio, BAM raso e log limpo e PC stopado: %+v", s)
	}
	if !strings.Contains(s[0].Detalhe, "Amcache (1705 programas)") || !strings.Contains(s[0].Detalhe, "ShimCache (800") {
		t.Fatalf("tem que dizer onde ainda da para procurar: %s", s[0].Detalhe)
	}
}

func TestRastrosSoSysMainEhAlertaFraco(t *testing.T) {
	instalado := time.Now().Add(-200 * 24 * time.Hour)
	r := RastrosDeExecucao{SysMainDesativado: true, PrefetchLido: true, PrefetchQuantidade: 0, BAMLido: true, BAMQuantidade: 300, AmcacheLido: true, AmcacheQuantidade: 900}
	s := avaliarRastrosDeExecucao(r, instalado, time.Now())
	if len(s) != 1 || s[0].Severidade != Alerta {
		t.Fatalf("SysMain desligado com Prefetch vazio e alerta, nao critico: %+v", s)
	}
}

func TestRastrosIntactosNaoAcusam(t *testing.T) {
	r := RastrosDeExecucao{PrefetchLido: true, PrefetchQuantidade: 320, BAMLido: true, BAMQuantidade: 120, AmcacheLido: true, AmcacheQuantidade: 1500, ShimCacheLido: true, ShimCacheQuantidade: 600}
	if s := avaliarRastrosDeExecucao(r, time.Now().Add(-90*24*time.Hour), time.Now()); s != nil {
		t.Fatalf("tudo registrando nao pode ter sinal: %+v", s)
	}
}

func TestRastrosWindowsNovoNaoPuneContagemBaixa(t *testing.T) {
	r := RastrosDeExecucao{PrefetchLido: true, PrefetchQuantidade: 8, BAMLido: true, BAMQuantidade: 5, AmcacheLido: true, AmcacheQuantidade: 20}
	if s := avaliarRastrosDeExecucao(r, time.Now().Add(-2*24*time.Hour), time.Now()); s != nil {
		t.Fatalf("Windows de 2 dias tem pouco rastro por natureza: %+v", s)
	}
}

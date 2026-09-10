package main

import (
	"strings"
	"testing"
	"time"
)

const pedAccuracyPadrao = `<?xml version="1.0" encoding="UTF-8"?>
<sPedAccuracyModifiers>
  <PLAYER_RECOIL_MODIFIER_MIN value="0.800000" />
  <PLAYER_RECOIL_MODIFIER_MAX value="1.000000" />
  <PLAYER_RECOIL_CROUCHED_MODIFIER value="0.500000" />
  <PLAYER_BLIND_FIRE_MODIFIER_MIN value="2.00000" />
  <PLAYER_BLIND_FIRE_MODIFIER_MAX value="4.000000" />
  <PLAYER_RECENTLY_DAMAGED_MODIFIER value="0.300000" />
  <AI_GLOBAL_MODIFIER value="2.000000" />
</sPedAccuracyModifiers>`

const pedAccuracyZerado = `<sPedAccuracyModifiers>
  <PLAYER_RECOIL_MODIFIER_MIN value="00000.000001" />
  <PLAYER_RECOIL_MODIFIER_MAX value="00000.000002" />
  <PLAYER_RECOIL_CROUCHED_MODIFIER value="0.000001" />
  <PLAYER_BLIND_FIRE_MODIFIER_MIN value="000.000001" />
  <PLAYER_BLIND_FIRE_MODIFIER_MAX value="000.0000002" />
  <PLAYER_RECENTLY_DAMAGED_MODIFIER value="0.300000" />
</sPedAccuracyModifiers>`

func metaDeTeste(nome, conteudo string) ArquivoDeMetadados {
	return ArquivoDeMetadados{
		Nome:       nome,
		Caminho:    `C:\Users\x\AppData\Local\FiveM\FiveM.app\citizen\common\data\ai\` + nome,
		Tamanho:    900,
		Modificado: time.Date(2026, 9, 8, 5, 42, 0, 0, time.Local),
		Valores:    lerValoresDeMetadados(conteudo),
	}
}

func TestLerValoresDeMetadados(t *testing.T) {
	v := lerValoresDeMetadados(pedAccuracyPadrao)
	if len(v) != 7 {
		t.Fatalf("esperava 7 valores, veio %d: %+v", len(v), v)
	}
	if v[0].Nome != "PLAYER_RECOIL_MODIFIER_MIN" || v[0].Valor != 0.8 {
		t.Fatalf("primeiro valor errado: %+v", v[0])
	}
	if lerValoresDeMetadados("<nada/>") != nil {
		t.Fatal("xml sem value nao produz valor")
	}
}

func TestPedAccuracyZeradoEhCritico(t *testing.T) {
	m := MetadadosDoJogo{Arquivos: []ArquivoDeMetadados{metaDeTeste("pedaccuracy.meta", pedAccuracyZerado)}}
	s := avaliarMetadadosDoJogo(m)
	if len(s) != 2 {
		t.Fatalf("esperava o sinal da pasta e o do pedaccuracy: %+v", s)
	}
	for _, x := range s {
		if x.Severidade != Critico {
			t.Fatalf("os dois sao criticos: %+v", x)
		}
	}
	var detalhes string
	for _, x := range s {
		detalhes += x.Detalhe
	}
	if !strings.Contains(detalhes, "praticamente zerados") {
		t.Fatalf("tem que dizer que os valores estao zerados: %s", detalhes)
	}
	if !strings.Contains(detalhes, "PLAYER_RECOIL_MODIFIER_MIN") || !strings.Contains(detalhes, "padrao do jogo: 0.8") {
		t.Fatalf("tem que mostrar o valor achado contra o padrao: %s", detalhes)
	}
	if strings.Contains(detalhes, "PLAYER_RECENTLY_DAMAGED_MODIFIER") {
		t.Fatalf("valor que bate com o padrao nao entra na lista: %s", detalhes)
	}
}

func TestPedAccuracyPadraoAindaEhCriticoPorEstarAli(t *testing.T) {
	m := MetadadosDoJogo{Arquivos: []ArquivoDeMetadados{metaDeTeste("pedaccuracy.meta", pedAccuracyPadrao)}}
	s := avaliarMetadadosDoJogo(m)
	if len(s) != 1 || s[0].Severidade != Critico {
		t.Fatalf("o arquivo nao devia existir nessa pasta, mesmo com valores padrao: %+v", s)
	}
	if !strings.Contains(s[0].Detalhe, "instalacao limpa do FiveM") {
		t.Fatalf("tem que explicar por que a pasta e anomalia: %s", s[0].Detalhe)
	}
}

func TestWeaponsMetaComPrecisaoZerada(t *testing.T) {
	conteudo := `<Item>
	  <AccuracySpread value="0.000000" />
	  <RecoilShakeAmplitude value="0.000000" />
	  <CameraRecoilScaling value="0.000000" />
	  <Damage value="30.000000" />
	</Item>`
	m := MetadadosDoJogo{Arquivos: []ArquivoDeMetadados{metaDeTeste("weapons.meta", conteudo)}}
	s := avaliarMetadadosDoJogo(m)
	if len(s) != 2 {
		t.Fatalf("esperava sinal da pasta e o da arma: %+v", s)
	}
	achou := false
	for _, x := range s {
		if strings.Contains(x.Titulo, "3 campo(s) de precisao zerado") && x.Severidade == Critico {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("tinha que apontar os tres campos zerados: %+v", s)
	}
}

func TestInstalacaoLimpaNaoGeraSinal(t *testing.T) {
	if avaliarMetadadosDoJogo(MetadadosDoJogo{Instalacao: `C:\FiveM.app`}) != nil {
		t.Fatal("sem .meta na pasta, sem sinal")
	}
}

func TestSettingsMetaDeControleNaoContaComoArma(t *testing.T) {
	a := metaDeTeste("settings.meta", `<Item><Deadzone value="0.000000" /></Item>`)
	if _, tem := desviosDeArma(a); tem {
		t.Fatal("settings.meta de tecla nao e arquivo de arma")
	}
	if _, tem := desviosDoPedAccuracy(a); tem {
		t.Fatal("settings.meta nao e pedaccuracy")
	}
}

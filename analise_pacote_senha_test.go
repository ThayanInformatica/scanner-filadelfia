package main

import (
	"strings"
	"testing"
	"time"
)

var listagemDoRarDoBypass = []string{
	"''3.F", "(g6.K", ").uZb6", ". ovm", ".RVTS", ".k6T2", ".vfvai", "8.CRG_", "8I.pxq",
	`EK\.Eav`, "Q6.6N", "R.STA", "RW7l.xw", "RpZ.Z", `Z(MgC.G\`, "b.F89", "c.NESA",
	"iYoU.3", "lhQ.Vz", "n.ASm", "nN.0q", "t.QLIv", "vkc.aU", "w.iJZz", "x).NL", "z.jQo",
}

func itensDeTeste(nomes []string) []ItemDePacote {
	var itens []ItemDePacote
	for _, n := range nomes {
		itens = append(itens, ItemDePacote{Nome: n})
	}
	return itens
}

func TestListagemDoRarCriptografadoEhLixo(t *testing.T) {
	if !listagemPareceLixo(itensDeTeste(listagemDoRarDoBypass)) {
		t.Fatal("a listagem raspada de um rar com senha tem que ser reconhecida como ilegivel")
	}
}

func TestListagemDeVerdadeNaoEhLixo(t *testing.T) {
	real := []string{
		`citizen/clr2/lib/mono/4.5/CitizenFX.Core.dll`, `citizen/clr2/lib/mono/4.5/System.dll`,
		`citizen/scripting/lua/json.lua`, `citizen/scripting/lua/scheduler.lua`,
		`citizen/scripting/v8/main.js`, `citizen/common/data/gameconfig.xml`,
		`leiame.txt`, `config.ini`,
	}
	if listagemPareceLixo(itensDeTeste(real)) {
		t.Fatal("listagem real nao pode ser confundida com lixo")
	}
	soltos := []string{"dControl.exe", "dControl.ini", "leiame.txt", "loader.exe", "config.json", "readme.md"}
	if listagemPareceLixo(itensDeTeste(soltos)) {
		t.Fatal("pacote sem pastas mas com nomes reais tambem nao e lixo")
	}
	if listagemPareceLixo(itensDeTeste([]string{"a.exe", "b.dll"})) {
		t.Fatal("listagem curta demais nao e julgada")
	}
}

func TestNomeDeArquivoPlausivel(t *testing.T) {
	for _, bom := range []string{"loader.exe", "CitizenFX.Core.dll", `pasta/sub/arquivo_1.lua`, "leia me.txt"} {
		if !nomeDeArquivoPlausivel(bom) {
			t.Errorf("%q e nome plausivel", bom)
		}
	}
	for _, ruim := range []string{"''3.F", "(g6.K", ".RVTS", `Z(MgC.G\`, "semponto", "x."} {
		if nomeDeArquivoPlausivel(ruim) {
			t.Errorf("%q nao e nome plausivel", ruim)
		}
	}
}

func TestRarComSenhaPorCabecalho(t *testing.T) {
	rar4Aberto := append([]byte("Rar!\x1a\x07\x00"), 0, 0, 0, 0x00, 0x00, 0, 0)
	if rarComSenha(rar4Aberto) {
		t.Fatal("rar4 sem a marca de senha nao pode acusar")
	}
	rar4Cripto := append([]byte("Rar!\x1a\x07\x00"), 0, 0, 0, 0x80, 0x00, 0, 0)
	if !rarComSenha(rar4Cripto) {
		t.Fatal("rar4 com o bit 0x0080 esta com o cabecalho criptografado")
	}
	rar5Cripto := append([]byte("Rar!\x1a\x07\x01\x00"), 0xAA, 0xBB, 0xCC, 0xDD, 0x10, 0x04, 0, 0)
	if !rarComSenha(rar5Cripto) {
		t.Fatal("rar5 cujo primeiro bloco e do tipo 4 esta criptografado")
	}
	rar5Aberto := append([]byte("Rar!\x1a\x07\x01\x00"), 0xAA, 0xBB, 0xCC, 0xDD, 0x10, 0x01, 0, 0)
	if rarComSenha(rar5Aberto) {
		t.Fatal("rar5 com bloco principal normal nao acusa")
	}
	if rarComSenha([]byte("PK\x03\x04qualquer coisa aqui")) {
		t.Fatal("zip nao e rar")
	}
}

func TestPacoteComSenhaNaoEhLiberado(t *testing.T) {
	a := assinaturasDeTeste(t)
	p := PacoteAnalisado{
		Caminho: `C:\Users\Vieli\Downloads\24122024.rar`, Formato: "rar",
		Modificado: time.Date(2026, 9, 11, 1, 15, 53, 0, time.Local), Tamanho: 5 << 20,
		ProtegidoPorSenha: true, Erro: "arquivo rar protegido por senha",
	}
	s := avaliarPacote(p, a)
	if len(s) != 1 || s[0].Severidade != Critico {
		t.Fatalf("pacote com senha em Downloads e critico: %+v", s)
	}
	if !strings.Contains(s[0].Titulo, "PROTEGIDO POR SENHA") || strings.Contains(s[0].Titulo, "nada suspeito") {
		t.Fatalf("nao pode liberar pacote que nao deu para abrir: %+v", s[0])
	}
	if !strings.Contains(s[0].Detalhe, "Peca a senha ao jogador") {
		t.Fatalf("tem que dizer o que fazer: %s", s[0].Detalhe)
	}

	fora := p
	fora.Caminho = `D:\backup\antigo\24122024.rar`
	if s := avaliarPacote(fora, a); s[0].Severidade != Alerta {
		t.Fatalf("fora de pasta quente e alerta, nao critico: %+v", s)
	}
}

func TestListagemIlegivelNaoLiberaOPacote(t *testing.T) {
	a := assinaturasDeTeste(t)
	p := PacoteAnalisado{
		Caminho: `C:\Users\Vieli\Downloads\pack.rar`, Formato: "rar",
		ListagemIlegivel: true, Erro: "a lista de arquivos saiu ilegivel",
	}
	s := avaliarPacote(p, a)
	if len(s) != 1 || s[0].Severidade != Critico || !strings.Contains(s[0].Titulo, "PROTEGIDO POR SENHA") {
		t.Fatalf("listagem ilegivel nao pode virar 'nada suspeito': %+v", s)
	}
}

func TestListaDeFiltroDeAnuncioNaoEhCheat(t *testing.T) {
	filtro := `adsbygoogle.js$xhr,redirect=noop.js,domain=unknowncheats.me *$xhr,redirect-rule=nooptext,domain=cheatglobal.com##+js(acs, addEventListener)`
	if !contextoDeListaDeFiltros(filtro) {
		t.Fatal("regra de adblock tem que ser reconhecida")
	}
	if contextoDeListaDeFiltros("local loader = require('eulen') -- inject into fivem") {
		t.Fatal("script de cheat nao pode passar por lista de filtro")
	}
	if contextoDeListaDeFiltros("") {
		t.Fatal("texto vazio nao e lista de filtro")
	}
}

func TestMetaDeInterfaceNaoEhCritico(t *testing.T) {
	ui := MetadadosDoJogo{Arquivos: []ArquivoDeMetadados{{
		Nome: "mapzoomdata.meta", Caminho: `C:\Users\x\AppData\Local\FiveM\FiveM.app\citizen\common\data\ui\mapzoomdata.meta`, Tamanho: 1024,
	}}}
	s := avaliarMetadadosDoJogo(ui)
	if len(s) != 1 || s[0].Severidade != Alerta || !strings.Contains(s[0].Detalhe, "zoom do minimapa") {
		t.Fatalf("meta de interface e alerta, nao critico: %+v", s)
	}
	arma := MetadadosDoJogo{Arquivos: []ArquivoDeMetadados{
		{Nome: "mapzoomdata.meta", Caminho: `...\citizen\common\data\ui\mapzoomdata.meta`},
		{Nome: "pedaccuracy.meta", Caminho: `...\citizen\common\data\ai\pedaccuracy.meta`},
	}}
	if s := avaliarMetadadosDoJogo(arma); s[0].Severidade != Critico {
		t.Fatalf("com arquivo de arma junto volta a ser critico: %+v", s)
	}
}

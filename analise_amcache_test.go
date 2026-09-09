package main

import (
	"strings"
	"testing"
)

func assinaturasComHash(t *testing.T) *Assinaturas {
	t.Helper()
	a, _, err := AssinaturasDeBytes([]byte(`{
		"cheats": ["eulen", "redengine"],
		"marcas": ["eulen"],
		"ferramentas": ["cheat engine"],
		"hashes": [
			"sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709 loader do eulen v3",
			"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 menu redengine",
			"lixo sem hash"
		]
	}`), "teste")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestIndiceDeHashesAceitaPrefixoERotulo(t *testing.T) {
	a := assinaturasComHash(t)
	if r := a.HashConhecido("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"); r != "loader do eulen v3" {
		t.Fatalf("sha1 com prefixo devia casar, veio %q", r)
	}
	if r := a.HashConhecido("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"); r != "menu redengine" {
		t.Fatalf("sha256 sem prefixo devia casar, veio %q", r)
	}
	if a.HashConhecido("0000") != "" || a.HashConhecido("") != "" {
		t.Fatal("hash invalido nao pode casar")
	}
}

func TestAmcacheAcusaNomeHashEApagado(t *testing.T) {
	a := assinaturasComHash(t)
	entradas := []EntradaAmcache{
		{Caminho: `c:\users\x\downloads\eulen_loader.exe`, SHA1: "1111111111111111111111111111111111111111", ExisteNoDisco: false},
		{Caminho: `c:\users\x\appdata\local\temp\qz8k1m2p.exe`, SHA1: "da39a3ee5e6b4b0d3255bfef95601890afd80709", ExisteNoDisco: false},
		{Caminho: `c:\users\x\appdata\local\temp\xk9f2m1pq7zt.exe`, SHA1: "2222222222222222222222222222222222222222", ExisteNoDisco: false},
		{Caminho: `c:\program files\cheat engine\cheatengine-x86_64.exe`, ExisteNoDisco: true},
		{Caminho: `c:\program files\google\chrome\application\chrome.exe`, ExisteNoDisco: true},
	}
	sinais := avaliarAmcache(entradas, a)
	titulos := ""
	for _, s := range sinais {
		titulos += s.Severidade.String() + " " + s.Titulo + "\n" + s.Detalhe + "\n"
	}
	for _, esperado := range []string{
		"CRITICO Amcache: 'eulen' JA RODOU",
		"NAO existe mais no disco",
		"CRITICO Amcache: programa com HASH de cheat conhecido ja rodou: qz8k1m2p.exe",
		"loader do eulen v3",
		"ALERTA Amcache: ferramenta de injecao/debug/macro 'cheat engine' ja rodou",
		"nome aleatorio rodaram de pasta temporaria",
		"xk9f2m1pq7zt.exe",
	} {
		if !strings.Contains(titulos, esperado) {
			t.Errorf("faltou %q em:\n%s", esperado, titulos)
		}
	}
	if strings.Contains(titulos, "chrome.exe") {
		t.Error("chrome nao pode aparecer como suspeito")
	}
}

func TestAmcacheVazioNaoAcusa(t *testing.T) {
	if s := avaliarAmcache(nil, assinaturasComHash(t)); s != nil {
		t.Fatalf("sem entradas nao pode ter sinal, veio %d", len(s))
	}
}

func TestMemoriaDeProcessoDistingueAssinadoDeSolto(t *testing.T) {
	solto := avaliarMemoriaDeProcesso("xk9.exe", `C:\Users\x\AppData\Roaming\xk9.exe`, "NotSigned", "", []string{"eulen", "aimbot"}, "eulen menu v3")
	if len(solto) != 1 || solto[0].Severidade != Critico || !strings.Contains(solto[0].Titulo, "NA MEMORIA de xk9.exe") {
		t.Fatalf("processo sem assinatura com string de cheat tem que ser critico: %+v", solto)
	}
	assinado := avaliarMemoriaDeProcesso("notepad++.exe", `C:\Program Files\Notepad++\notepad++.exe`, "Valid", "CN=Notepad++", []string{"eulen"}, "")
	if len(assinado) != 1 || assinado[0].Severidade != Alerta || !strings.Contains(assinado[0].Detalhe, "documento ou texto sobre cheat") {
		t.Fatalf("programa assinado com texto de cheat tem que ser alerta explicando: %+v", assinado)
	}
	if avaliarMemoriaDeProcesso("a.exe", "", "", "", nil, "") != nil {
		t.Fatal("sem termo nao pode ter sinal")
	}
}

func TestProcessosForaDaVarreduraDeMemoria(t *testing.T) {
	casos := []struct {
		nome, caminho, assinante string
		fora                     bool
	}{
		{"chrome.exe", `C:\Program Files\Google\Chrome\chrome.exe`, "Google LLC", true},
		{"Discord.exe", `C:\Users\x\AppData\Local\Discord\Discord.exe`, "Discord Inc.", true},
		{"FiveM_GTAProcess.exe", `C:\Users\x\AppData\Local\FiveM\FiveM.app\FiveM_GTAProcess.exe`, "", true},
		{"svchost.exe", `C:\Windows\System32\svchost.exe`, "Microsoft Windows", true},
		{"EasyAntiCheat.exe", `C:\Program Files\EasyAntiCheat\EasyAntiCheat.exe`, "Epic Games Inc.", true},
		{"Steam.exe", `C:\Program Files (x86)\Steam\Steam.exe`, "Valve Corp.", true},
		{"obs64.exe", `C:\Program Files\obs-studio\bin\64bit\obs64.exe`, "Hugh Bailey", false},
		{"xk9.exe", `C:\Users\x\AppData\Roaming\xk9.exe`, "", false},
		{"semcaminho.exe", "", "", true},
	}
	for _, c := range casos {
		if got := processoForaDaVarreduraDeMemoria(c.nome, c.caminho, c.assinante); got != c.fora {
			t.Errorf("%s: fora=%v, esperado %v", c.nome, got, c.fora)
		}
	}
}

package main

import (
	"strings"
	"testing"
)

func TestMemoriaDeDadosAcusaScriptDeLua(t *testing.T) {
	s := avaliarMemoriaDeDadosDoJogo([]AchadoDeDados{
		{Endereco: 0x1E4A0000, Termos: []string{"eulen"}, Contexto: "-- eulen menu v3 loaded"},
		{Endereco: 0x1E4B0000, Termos: []string{"lua executor"}, Contexto: "lua executor ready"},
	}, 900*1024*1024, "FiveM_GTAProcess.exe")
	if len(s) != 2 {
		t.Fatalf("dois termos, dois sinais: %+v", s)
	}
	for _, sinal := range s {
		if sinal.Severidade != Critico || !strings.Contains(sinal.Titulo, "MEMORIA DE DADOS") {
			t.Fatalf("string de cheat na memoria de dados e critico: %+v", sinal)
		}
	}
	if !strings.Contains(s[0].Detalhe, "lua_State") {
		t.Fatalf("o detalhe tem que explicar o executor de Lua: %s", s[0].Detalhe)
	}
	if avaliarMemoriaDeDadosDoJogo(nil, 100, "x.exe") != nil {
		t.Fatal("sem achado, sem sinal")
	}
}

func TestThreadForaDeModuloEhCritico(t *testing.T) {
	threads := []ThreadAnalisada{
		{TID: 100, Inicial: 0x7FFAA000, Modulo: "ntdll.dll"},
		{TID: 101, Inicial: 0x20000000, TipoDaRegiao: "privada (sem arquivo)", Protecao: "RX", TemPE: true},
		{TID: 102, Inicial: 0x30000000, TipoDaRegiao: "arquivo mapeado", Protecao: "RX"},
		{TID: 103, Inicial: 0},
	}
	s := avaliarThreadsDoJogo(threads, "FiveM_GTAProcess.exe")
	if len(s) != 2 {
		t.Fatalf("uma privada (critico) e uma mapeada (alerta): %+v", s)
	}
	if s[0].Severidade != Critico || !strings.Contains(s[0].Detalhe, "thread 101") || !strings.Contains(s[0].Detalhe, "PE") {
		t.Fatalf("thread em memoria privada com PE e critico: %+v", s[0])
	}
	if s[1].Severidade != Alerta || !strings.Contains(s[1].Detalhe, "V8") {
		t.Fatalf("regiao mapeada e alerta com ressalva de JIT: %+v", s[1])
	}
	limpo := []ThreadAnalisada{{TID: 1, Inicial: 0x7FFAA000, Modulo: "ntdll.dll"}, {TID: 2, Inicial: 0, Modulo: ""}}
	if s := avaliarThreadsDoJogo(limpo, "x.exe"); s != nil {
		t.Fatalf("threads normais nao acusam: %+v", s)
	}
}

func TestHookParaMemoriaPrivadaEhCritico(t *testing.T) {
	hooks := []HookDetectado{
		{Modulo: "ntdll.dll", Deslocamento: 0x9C120, Endereco: 0x7FF89C120, Destino: 0x21000000, TipoDoDestino: "privada (sem arquivo)", BytesEmMemoria: "E9 DB", BytesNoDisco: "4C 8B"},
		{Modulo: "kernel32.dll", Deslocamento: 0x1000, Endereco: 0x7FF81000, Destino: 0x7FF70000, ModuloDoDestino: "avghookx.dll", BytesEmMemoria: "E9 00", BytesNoDisco: "48 89"},
		{Modulo: "dxgi.dll", Deslocamento: 0x2000, Endereco: 0x7FF82000, Destino: 0x7FF60000, ModuloDoDestino: "ReShade64.dll", BytesEmMemoria: "E9 11", BytesNoDisco: "48 8B"},
	}
	s := avaliarHooks(hooks, "FiveM_GTAProcess.exe")
	if len(s) != 3 {
		t.Fatalf("esperava um por destino/modulo: %+v", s)
	}
	if s[0].Severidade != Critico || !strings.Contains(s[0].Titulo, "sem arquivo") {
		t.Fatalf("desvio para memoria privada e critico: %+v", s[0])
	}
	achouAlerta, achouInfo := false, false
	for _, x := range s[1:] {
		if strings.Contains(x.Titulo, "kernel32.dll") && x.Severidade == Alerta {
			achouAlerta = true
		}
		if strings.Contains(x.Titulo, "ReShade") && strings.Contains(x.Detalhe, "dxgi.dll") && x.Severidade == Info {
			achouInfo = true
		}
	}
	if !achouAlerta || !achouInfo {
		t.Fatalf("kernel32 e alerta, dxgi grafica e informativo: %+v", s)
	}
	if avaliarHooks(nil, "x.exe") != nil {
		t.Fatal("sem hook, sem sinal")
	}
}

func TestDestinoDoDesvio(t *testing.T) {
	if d, ok := destinoDoDesvio([]byte{0xE9, 0x0B, 0x00, 0x00, 0x00}, 0x1000); !ok || d != 0x1010 {
		t.Fatalf("jmp rel32: %#x %v", d, ok)
	}
	imm := []byte{0x48, 0xB8, 0x00, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0}
	if d, ok := destinoDoDesvio(imm, 0x1000); !ok || d != 0x201000 {
		t.Fatalf("mov rax,imm64 + jmp rax: %#x %v", d, ok)
	}
	if _, ok := destinoDoDesvio([]byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}, 0x1000); !ok {
		t.Fatal("jmp indireto tem que ser reconhecido como desvio")
	}
	if _, ok := destinoDoDesvio([]byte{0x48, 0x89, 0x5C, 0x24}, 0x1000); ok {
		t.Fatal("prologo normal nao e desvio")
	}
}

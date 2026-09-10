package main

import (
	"strings"
	"testing"
	"time"
)

func memoriaFalsa(regioes map[uint64][]byte) func(uint64, int) []byte {
	return func(endereco uint64, tamanho int) []byte {
		for base, dados := range regioes {
			if endereco >= base && endereco < base+uint64(len(dados)) {
				ini := int(endereco - base)
				fim := ini + tamanho
				if fim > len(dados) {
					fim = len(dados)
				}
				return dados[ini:fim]
			}
		}
		return nil
	}
}

func TestSeguirDesviosAtravessaTrampolimDoMinHook(t *testing.T) {
	relay := []byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x7A, 0xFE, 0x7F, 0x00, 0x00, 0xCC, 0xCC}
	ler := memoriaFalsa(map[uint64][]byte{0x7FFE3C790F54: relay})
	site := []byte{0xE9, 0x4F, 0x99, 0xB7, 0x01, 0xB6, 0x75, 0x1B}
	final, saltos := seguirDesvios(site, 0x7FFE3AC17600, ler, 4)
	if final != 0x7FFE7A400000 || saltos != 1 {
		t.Fatalf("esperava o destino real 0x7FFE7A400000 depois de 1 salto, veio 0x%X em %d saltos", final, saltos)
	}
	semRelay := memoriaFalsa(nil)
	final, saltos = seguirDesvios(site, 0x7FFE3AC17600, semRelay, 4)
	if final != 0x7FFE3C790F54 || saltos != 0 {
		t.Fatalf("sem conseguir ler o trampolim, fica no primeiro destino: 0x%X %d", final, saltos)
	}
	ponteiro := []byte{0x00, 0x00, 0x50, 0x7A, 0xFE, 0x7F, 0x00, 0x00}
	lerPonteiro := memoriaFalsa(map[uint64][]byte{0x7FFE3C84D556 + 0x100: ponteiro})
	indireto := []byte{0xFF, 0x25, 0x00, 0x01, 0x00, 0x00, 0xCC, 0xCC}
	final, _ = seguirDesvios(indireto, 0x7FFE3C84D550, lerPonteiro, 4)
	if final != 0x7FFE7A500000 {
		t.Fatalf("jmp [rip+disp] tem que ler o ponteiro: 0x%X", final)
	}
}

func TestHooksDoProprioFiveMSaoInformativos(t *testing.T) {
	hooks := []HookDetectado{
		{Modulo: "KERNEL32.DLL", Deslocamento: 0x17600, Endereco: 0x7FFE3AC17600, Destino: 0x7FFE3C790F54, DestinoFinal: 0x7FFE7A400000, Saltos: 1, ModuloDoDestino: "CoreRT.dll", CaminhoDoDestino: `C:\Users\Nardo\AppData\Local\FiveM\FiveM.app\CoreRT.dll`, BytesEmMemoria: "E9 4F", BytesNoDisco: "48 83"},
		{Modulo: "WININET.dll", Deslocamento: 0x515A0, Endereco: 0x7FFE273115A0, Destino: 0x7FFE3B8F09D5, DestinoFinal: 0x7FFE7A410000, Saltos: 1, ModuloDoDestino: "ros-patches-five.dll", CaminhoDoDestino: `C:\Users\Nardo\AppData\Local\FiveM\FiveM.app\ros-patches-five.dll`, BytesEmMemoria: "E9 30", BytesNoDisco: "48 8B"},
		{Modulo: "ntdll.dll", Deslocamento: 0x9D550, Endereco: 0x7FFE3C84D550, Destino: 0x7FFDE573C800, DestinoFinal: 0x7FFDE573C800, ModuloDoDestino: "chrome_elf.dll", CaminhoDoDestino: `C:\Users\Nardo\AppData\Local\FiveM\FiveM.app\bin\chrome_elf.dll`, BytesEmMemoria: "48 B8", BytesNoDisco: "4C 8B"},
		{Modulo: "KERNELBASE.dll", Deslocamento: 0x30190, Endereco: 0x7FFE3A040190, Destino: 0x7FFE3C7A0F17, DestinoFinal: 0x7FFE3C7A0F17, TipoDoDestino: "privada (sem arquivo)", BytesEmMemoria: "E9 82", BytesNoDisco: "48 83"},
	}
	sinais := avaliarHooks(hooks, "FiveM_b3258_GTAProcess.exe")
	if len(sinais) != 2 {
		t.Fatalf("esperava critico da privada + um informativo agrupando tudo do FiveM: %+v", sinais)
	}
	if sinais[0].Severidade != Critico || !strings.Contains(sinais[0].Titulo, "1 funcao") {
		t.Fatalf("so a que continua em memoria privada e critica: %+v", sinais[0])
	}
	for _, s := range sinais[1:] {
		if s.Severidade != Info || !strings.Contains(s.Titulo, "dono conhecido") {
			t.Fatalf("hook do FiveM e do CEF e informativo: %+v", s)
		}
	}
	if !strings.Contains(sinais[1].Detalhe, "trampolim e segue ate 0x7FFE7A400000") || !strings.Contains(sinais[1].Detalhe, "chrome_elf.dll") || !strings.Contains(sinais[1].Titulo, "3 desvio") {
		t.Fatalf("o detalhe tem que mostrar o destino depois do trampolim e juntar os tres: %+v", sinais[1])
	}
}

func TestPacoteDoProprioScannerEhInformativo(t *testing.T) {
	a := assinaturasDeTeste(t)
	itens := []ItemDePacote{{Nome: "scanner.exe", Tamanho: 19000000}, {Nome: "teste/plantar.ps1", Tamanho: 6000}, {Nome: "teste/verificar.exe", Tamanho: 4000000}, {Nome: "TRANSPARENCIA.md", Tamanho: 6000}}
	s := avaliarPacote(PacoteAnalisado{Caminho: `C:\Users\Nardo\Downloads\scannerfiladelfia2.13.0EQUIPE.zip`, Formato: "zip", Itens: itens}, a)
	if len(s) != 1 || s[0].Severidade != Info || !strings.Contains(s[0].Titulo, "proprio Scanner") {
		t.Fatalf("o kit do scanner nao pode virar alerta: %+v", s)
	}
}

func TestPacoteCitizenComArquivoSoltoEhCritico(t *testing.T) {
	a := assinaturasDeTeste(t)
	itens := []ItemDePacote{{Nome: "8pf.JS"}, {Nome: "l.DLl"}}
	for _, n := range []string{"CitizenFX.Core.Client.dll", "CitizenFX.Core.dll", "Mono.CSharp.dll", "System.Core.dll", "mscorlib.dll", "v2/CitizenFX.FiveM.dll"} {
		itens = append(itens, ItemDePacote{Nome: "silvathek1ng/citizen/clr2/lib/mono/4.5/" + n})
	}
	s := avaliarPacote(PacoteAnalisado{Caminho: `C:\Users\Nardo\Downloads\400kpriv.rar`, Formato: "rar", Itens: itens}, a)
	if len(s) != 1 || s[0].Severidade != Critico || !strings.Contains(s[0].Titulo, "2 arquivo(s) que nao pertencem") {
		t.Fatalf("citizen + js + dll soltos e critico: %+v", s)
	}
	if !strings.Contains(s[0].Detalhe, "l.DLl  (extensao com letras trocadas") || !strings.Contains(s[0].Detalhe, "8pf.JS") {
		t.Fatalf("tem que apontar os dois soltos e a extensao disfarcada: %s", s[0].Detalhe)
	}
}

func TestPacoteCitizenComNomeDePessoaEhAlerta(t *testing.T) {
	a := assinaturasDeTeste(t)
	var itens []ItemDePacote
	for _, n := range []string{"clr2/lib/mono/4.5/CitizenFX.Core.dll", "clr2/lib/mono/4.5/mscorlib.dll", "scripting/lua/json.lua", "scripting/lua/natives_universal.lua", "scripting/v8/main.js", "shaderz/makeshader.cmd", "ui.zip"} {
		itens = append(itens, ItemDePacote{Nome: "Citizen Klinn/" + n, Tamanho: 1000})
	}
	s := avaliarPacote(PacoteAnalisado{Caminho: `C:\Users\Nardo\Downloads\Citizen Klinn-20260908T224102Z-1-001.zip`, Formato: "zip", Itens: itens}, a)
	if len(s) != 1 || s[0].Severidade != Alerta || !strings.Contains(s[0].Titulo, "troca de citizen") {
		t.Fatalf("citizen completa sem arquivo estranho e alerta de troca de citizen: %+v", s)
	}
}

func TestConteudoInternoDaCitizenNaoEhPacote(t *testing.T) {
	for _, n := range []string{"natives_0193D0AF.zip", "natives_universal.zip", "ny_universal.zip", "rdr3_universal.zip", "natives_server.zip", "ui.zip", "ui-big.zip"} {
		if !conteudoInternoDaCitizen(n) {
			t.Errorf("%s e conteudo interno da citizen", n)
		}
	}
	for _, n := range []string{"citizen.zip", "natives.zip", "ui-mod.zip", "400kpriv.rar"} {
		if conteudoInternoDaCitizen(n) {
			t.Errorf("%s nao e conteudo interno da citizen", n)
		}
	}
}

func TestDadosDeJogoInstaladoCobreRoblox(t *testing.T) {
	if dadosDeJogoInstalado(`C:\Users\Nardo\AppData\Local\Roblox\rbx-storage\6a\6a03930c24b5462b28b7f12b07367efc`) == "" {
		t.Fatal("cache do Roblox e dado de jogo")
	}
	if dadosDeJogoInstalado(`D:\SteamLibrary\steamapps\common\House Party\HouseParty_Data\x.assets`) == "" {
		t.Fatal("steamapps continua coberto")
	}
	if dadosDeJogoInstalado(`C:\Users\Nardo\Downloads\eulen.txt`) != "" {
		t.Fatal("Downloads nao e dado de jogo")
	}
}

func TestCitizenSoltaIdenticaComMesmaDataEhCritico(t *testing.T) {
	data := time.Date(2026, 9, 8, 5, 42, 58, 0, time.Local)
	dataDoFiveM := time.Date(2026, 9, 1, 10, 0, 0, 0, time.Local)
	copia := []ArquivoDaCitizen{
		{Relativo: `clr2\lib\mono\4.5\CitizenFX.Core.dll`, Hash: "aaa", Modificado: data, Existe: true},
		{Relativo: `clr2\lib\mono\4.5\mscorlib.dll`, Hash: "bbb", Modificado: data, Existe: true},
		{Relativo: `scripting\v8\main.js`, Existe: false},
	}
	instalada := []ArquivoDaCitizen{
		{Relativo: `clr2\lib\mono\4.5\CitizenFX.Core.dll`, Hash: "aaa", Modificado: data, Existe: true},
		{Relativo: `clr2\lib\mono\4.5\mscorlib.dll`, Hash: "bbb", Modificado: dataDoFiveM, Existe: true},
		{Relativo: `scripting\v8\main.js`, Hash: "ccc", Modificado: dataDoFiveM, Existe: true},
	}
	s := avaliarCitizenSolta(CitizenSolta{Raiz: `C:\Users\Nardo\Desktop\citizen\Citizen Klinn`, Arquivos: copia, Instalada: instalada}, `C:\Users\Nardo\AppData\Local\FiveM\FiveM.app\citizen`)
	if len(s) != 1 || s[0].Severidade != Critico || !strings.Contains(s[0].Detalhe, "FOI TROCADA") {
		t.Fatalf("instalado identico e com a mesma data da copia = trocada: %+v", s)
	}

	instalada[0].Modificado = dataDoFiveM
	instalada[1].Modificado = dataDoFiveM
	s = avaliarCitizenSolta(CitizenSolta{Raiz: `C:\Users\Nardo\Desktop\citizen`, Arquivos: copia, Instalada: instalada}, "x")
	if len(s) != 1 || s[0].Severidade != Alerta {
		t.Fatalf("identico mas com data do atualizador e alerta: %+v", s)
	}

	instalada[0].Hash = "zzz"
	s = avaliarCitizenSolta(CitizenSolta{Raiz: `C:\Users\Nardo\Desktop\citizen`, Arquivos: copia, Instalada: instalada}, "x")
	if len(s) != 1 || s[0].Severidade != Critico || !strings.Contains(s[0].Titulo, "1 arquivo(s) diferente(s)") {
		t.Fatalf("CitizenFX.Core.dll diferente da instalada e critico: %+v", s)
	}
	if avaliarCitizenSolta(CitizenSolta{Raiz: "x", Arquivos: []ArquivoDaCitizen{{Relativo: "a", Existe: false}}, Instalada: instalada}, "x") != nil {
		t.Fatal("sem arquivo na copia, sem sinal")
	}
}

func TestDataSoltaNaCitizenInstalada(t *testing.T) {
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.Local)
	var arquivos []ArquivoDaCitizen
	for i, rel := range arquivosChaveDaCitizen {
		a := ArquivoDaCitizen{Relativo: rel, Existe: true, Modificado: base.Add(time.Duration(i) * time.Minute)}
		arquivos = append(arquivos, a)
	}
	if avaliarDatasDaCitizenInstalada(arquivos, "x") != nil {
		t.Fatal("todos gravados na mesma leva: nada")
	}
	arquivos[0].Modificado = time.Date(2026, 9, 8, 5, 42, 58, 0, time.Local)
	s := avaliarDatasDaCitizenInstalada(arquivos, "x")
	if len(s) != 1 || s[0].Severidade != Critico || !strings.Contains(s[0].Detalhe, "CitizenFX.Core.dll") {
		t.Fatalf("CitizenFX.Core.dll com data de uma semana depois dos vizinhos e troca manual: %+v", s)
	}
	for i := range arquivos {
		arquivos[i].Modificado = base.Add(time.Duration(i) * 48 * time.Hour)
	}
	if avaliarDatasDaCitizenInstalada(arquivos, "x") != nil {
		t.Fatal("datas todas espalhadas nao acusa ninguem")
	}
}

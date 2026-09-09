package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type EventoUSN struct {
	Nome   string
	Motivo string
	Hora   time.Time
}

type TarefaAgendada struct {
	Nome    string
	Comando string
	Autor   string
	Estado  string
	Proxima string
	Criacao time.Time
}

type StreamOculto struct {
	Arquivo string
	Stream  string
	Tamanho int64
}

func motivoUSNLegivel(motivo string) string {
	m := strings.ToLower(motivo)
	switch {
	case strings.Contains(m, "file delete"):
		return "apagado"
	case strings.Contains(m, "rename new name"):
		return "renomeado"
	case strings.Contains(m, "file create"):
		return "criado"
	case strings.Contains(m, "data overwrite"), strings.Contains(m, "data extend"):
		return "escrito"
	}
	return strings.TrimSpace(motivo)
}

func lerUSNCsv(r io.Reader, maxLinhas int, interessa func(nome string) bool) ([]EventoUSN, int, error) {
	leitor := csv.NewReader(r)
	leitor.FieldsPerRecord = -1
	leitor.LazyQuotes = true
	var eventos []EventoUSN
	var cabecalho []string
	total := 0
	for total < maxLinhas {
		linha, err := leitor.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(linha) < 3 {
			continue
		}
		if cabecalho == nil {
			cabecalho = linha
			continue
		}
		total++
		nome, motivo, hora := "", "", ""
		for i, campo := range linha {
			if i >= len(cabecalho) {
				break
			}
			chave := strings.ToLower(strings.TrimSpace(cabecalho[i]))
			switch chave {
			case "file name", "filename", "name", "nome do arquivo":
				nome = strings.TrimSpace(campo)
			case "reason", "motivo":
				motivo = strings.TrimSpace(campo)
			case "time stamp", "timestamp", "time", "data/hora":
				hora = strings.TrimSpace(campo)
			}
		}
		if nome == "" || !interessa(nome) {
			continue
		}
		e := EventoUSN{Nome: nome, Motivo: motivoUSNLegivel(motivo)}
		for _, formato := range []string{"1/2/2006 15:04:05", "02/01/2006 15:04:05", "2006-01-02 15:04:05", time.RFC3339} {
			if t, err := time.Parse(formato, hora); err == nil {
				e.Hora = t.Local()
				break
			}
		}
		eventos = append(eventos, e)
	}
	return eventos, total, nil
}

func avaliarUSN(volume string, eventos []EventoUSN, total int, a *Assinaturas) []Sinal {
	var sinais []Sinal
	porTermo := map[string][]EventoUSN{}
	var ordem []string
	for _, e := range eventos {
		termo := a.Marca(e.Nome)
		if termo == "" {
			classe, t := a.Classificar(e.Nome)
			if classe == SemMatch {
				continue
			}
			termo = t
		}
		if _, ok := porTermo[termo]; !ok {
			ordem = append(ordem, termo)
		}
		porTermo[termo] = append(porTermo[termo], e)
	}
	sort.Strings(ordem)
	for _, termo := range ordem {
		lista := porTermo[termo]
		var linhas []string
		apagados := 0
		for _, e := range lista {
			if e.Motivo == "apagado" {
				apagados++
			}
			linhas = append(linhas, fmt.Sprintf("%s  %s  (%s)", formataHora(e.Hora), e.Nome, e.Motivo))
		}
		detalhe := strings.Join(limitaLinhas(linhas, 60), "\n")
		detalhe += "\nO journal do NTFS guarda o nome de cada arquivo criado, renomeado e APAGADO no disco " + volume + ". Isso vale mesmo que o arquivo nao exista mais e a lixeira esteja vazia"
		titulo := fmt.Sprintf("Journal do disco %s registrou arquivo com assinatura '%s' (%d evento(s))", volume, termo, len(lista))
		if apagados > 0 {
			titulo = fmt.Sprintf("Arquivo com assinatura '%s' foi APAGADO do disco %s (journal do NTFS)", termo, volume)
		}
		sinais = append(sinais, Sinal{Critico, titulo, detalhe, "cheat"})
	}
	return sinais
}

func avaliarTarefas(tarefas []TarefaAgendada, a *Assinaturas) []Sinal {
	var sinais []Sinal
	for _, t := range tarefas {
		texto := t.Nome + " " + t.Comando
		nome := strings.TrimSpace(t.Nome)
		if strings.HasPrefix(strings.ToLower(nome), `\microsoft\`) && a.Marca(texto) == "" {
			continue
		}
		rotulo := nome + "  ->  " + resumeTexto(t.Comando, 160)
		if termo := a.Marca(texto); termo != "" {
			sinais = append(sinais, Sinal{Critico, "Tarefa agendada aponta para cheat ('" + termo + "'): " + nome, rotulo + "\nAutor: " + t.Autor + "  Estado: " + t.Estado + "\nTarefa agendada faz o programa voltar sozinho depois de reiniciar", "cheat"})
			continue
		}
		if classe, termo := a.Classificar(texto); classe != SemMatch && !a.TextoInocente(texto) {
			sinais = append(sinais, Sinal{classe.Severidade(), "Tarefa agendada bate com '" + termo + "': " + nome, rotulo + "\nAutor: " + t.Autor + "  Estado: " + t.Estado, "suspeito"})
			continue
		}
		if motivo := comandoDeOcultacao(t.Comando); motivo != "" {
			sinais = append(sinais, Sinal{Critico, "Tarefa agendada de ocultacao (" + motivo + "): " + nome, rotulo + "\nAutor: " + t.Autor + "  Estado: " + t.Estado + "\nAlguem agendou a limpeza de rastros para rodar sozinha", "cheat"})
			continue
		}
		if motivo := caminhoSuspeito(t.Comando); motivo != "" {
			sinais = append(sinais, Sinal{Alerta, "Tarefa agendada roda programa " + motivo + ": " + nome, rotulo + "\nAutor: " + t.Autor + "  Estado: " + t.Estado, "suspeito"})
		}
	}
	return ordenaSinais(sinais)
}

var streamsConhecidos = map[string]bool{
	"zone.identifier": true, "smartscreen": true, "wofcompresseddata": true, "encryptable": true,
	"favicon": true, "ms-properties": true, "kdstream": true, "dropboxrev": true, "com.dropbox.attributes": true,
	"onedrive": true, "afp_afpinfo": true, "afp_resource": true, "com.apple.quarantine": true,
}

func avaliarStreamsOcultos(streams []StreamOculto, a *Assinaturas) []Sinal {
	var sinais []Sinal
	var suspeitos []string
	for _, s := range streams {
		nome := strings.ToLower(strings.TrimSuffix(s.Stream, ":$DATA"))
		nome = strings.TrimPrefix(nome, ":")
		if nome == "" || streamsConhecidos[nome] {
			continue
		}
		linha := fmt.Sprintf("%s:%s  (%d KB)", s.Arquivo, nome, s.Tamanho/1024)
		if termo := a.Marca(s.Arquivo + " " + nome); termo != "" {
			sinais = append(sinais, Sinal{Critico, "Arquivo escondido em fluxo alternativo com nome de cheat ('" + termo + "')", linha + "\nUm Alternate Data Stream guarda um arquivo inteiro grudado em outro, invisivel no Explorer e na busca comum", "cheat"})
			continue
		}
		if s.Tamanho >= 64*1024 {
			sinais = append(sinais, Sinal{Alerta, "Arquivo grande escondido em fluxo alternativo (ADS): " + s.Arquivo, linha + "\nUm Alternate Data Stream desse tamanho carrega um programa ou pacote inteiro escondido dentro de outro arquivo. E um dos jeitos classicos de esconder cheat de quem olha o Explorer", "suspeito"})
			continue
		}
		suspeitos = append(suspeitos, linha)
	}
	sort.Strings(suspeitos)
	if len(suspeitos) > 0 {
		sinais = append(sinais, Sinal{Info, fmt.Sprintf("Fluxos alternativos (ADS) fora do padrao: %d", len(suspeitos)), strings.Join(limitaLinhas(suspeitos, 100), "\n"), ""})
	}
	return ordenaSinais(sinais)
}

type ResultadoBuscaLivre struct {
	Termo    string
	Arquivos []string
	Registro []string
	Memoria  []string
	Journal  []string
	Total    int
}

func (r ResultadoBuscaLivre) Vazio() bool {
	return len(r.Arquivos) == 0 && len(r.Registro) == 0 && len(r.Memoria) == 0 && len(r.Journal) == 0
}

var reProximaUSN = regexp.MustCompile(`(?i)(next usn|pr.xim[ao] usn|usn seguinte)\s*:\s*(0x[0-9a-f]+|\d+)`)

var rePrimeiraUSN = regexp.MustCompile(`(?i)(first usn|primeir[ao] usn|usn inicial)\s*:\s*(0x[0-9a-f]+|\d+)`)

func numeroUSN(texto string) uint64 {
	texto = strings.ToLower(strings.TrimSpace(texto))
	if strings.HasPrefix(texto, "0x") {
		v, _ := strconv.ParseUint(texto[2:], 16, 64)
		return v
	}
	v, _ := strconv.ParseUint(texto, 10, 64)
	return v
}

func pontoDePartidaUSN(saidaQueryJournal string, janela uint64) uint64 {
	m := reProximaUSN.FindStringSubmatch(saidaQueryJournal)
	if m == nil {
		return 0
	}
	proxima := numeroUSN(m[2])
	inicio := uint64(0)
	if proxima > janela {
		inicio = proxima - janela
	}
	if f := rePrimeiraUSN.FindStringSubmatch(saidaQueryJournal); f != nil {
		if primeira := numeroUSN(f[2]); primeira > inicio {
			inicio = primeira
		}
	}
	return inicio
}

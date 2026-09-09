//go:build windows

package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

func checarJournalDoDisco(c *Contexto) {
	r := c.R
	buscador := NovoBuscador(append(append([]string{}, c.A.Marcas...), c.A.Cheats...))
	interessa := func(nome string) bool {
		achou := false
		buscador.Procurar([]byte(nome), func(o Ocorrencia) bool { achou = true; return false })
		return achou
	}
	for _, unidade := range unidadesFixas() {
		letra := strings.TrimSuffix(unidade, `\`)
		r.Progresso("Lendo o journal do NTFS de %s (nomes de arquivos criados e apagados)", letra)
		var eventos []EventoUSN
		total := 0
		inicio := time.Now()
		args := []string{"usn", "readjournal", letra, "csv"}
		if inicioUSN := usnRecente(letra); inicioUSN > 0 {
			args = []string{"usn", "readjournal", letra, fmt.Sprintf("startusn=%d", inicioUSN), "csv"}
		}
		const tetoDeRegistros = 40000000
		err := executarStreamCancelavel(c.LimiteEtapa, c.DevePular, func(saida io.Reader) error {
			var err error
			eventos, total, err = lerUSNCsv(saida, tetoDeRegistros, interessa)
			return err
		}, "fsutil", args...)
		switch {
		case err == errCancelado:
			r.Linha("Journal de %s: leitura interrompida a pedido com %d registros lidos", letra, total)
		case err == errTempoEsgotado:
			r.Add(Alerta, "LEITURA DO JOURNAL DE "+letra+" INCOMPLETA: parou por tempo", fmt.Sprintf("%d registros lidos em %s antes do limite. Rode sem limite para ler tudo", total, time.Since(inicio).Round(time.Second)))
		case err != nil:
			r.Erro("journal de %s: %v", letra, err)
			continue
		case total >= tetoDeRegistros:
			r.Add(Alerta, "LEITURA DO JOURNAL DE "+letra+" INCOMPLETA: journal maior que o teto", fmt.Sprintf("Parei em %d registros. O journal e maior que isso e a parte mais antiga ficou de fora", total))
		}
		r.Linha("Journal de %s: %d registros lidos em %s", letra, total, time.Since(inicio).Round(time.Second))
		sinais := avaliarUSN(letra, eventos, total, c.A)
		for _, s := range sinais {
			r.Add(s.Severidade, s.Titulo, s.Detalhe)
		}
		if len(sinais) == 0 && total > 0 {
			r.Ok("Nenhum arquivo com nome de cheat no journal de %s", letra)
		}
	}
}

var reProximaUSN = regexp.MustCompile(`(?i)(next usn|pr.xima usn|usn seguinte)\s*:\s*(0x[0-9a-f]+|\d+)`)

func usnRecente(volume string) uint64 {
	saida, err := executar("fsutil", "usn", "queryjournal", volume)
	if err != nil {
		return 0
	}
	m := reProximaUSN.FindStringSubmatch(saida)
	if m == nil {
		return 0
	}
	texto := strings.ToLower(m[2])
	var proxima uint64
	if strings.HasPrefix(texto, "0x") {
		v, err := strconv.ParseUint(texto[2:], 16, 64)
		if err != nil {
			return 0
		}
		proxima = v
	} else {
		v, err := strconv.ParseUint(texto, 10, 64)
		if err != nil {
			return 0
		}
		proxima = v
	}
	const janela = 400 * 1024 * 1024
	if proxima > janela {
		return proxima - janela
	}
	return 0
}

func limiteOuPadrao(limite, padrao time.Duration) time.Duration {
	if limite > 0 {
		return limite
	}
	return padrao
}

func lerTarefasAgendadas() ([]TarefaAgendada, error) {
	saida, err := executar("schtasks", "/query", "/fo", "csv", "/v")
	if err != nil {
		return nil, err
	}
	leitor := csv.NewReader(strings.NewReader(saida))
	leitor.FieldsPerRecord = -1
	leitor.LazyQuotes = true
	registros, err := leitor.ReadAll()
	if err != nil && len(registros) == 0 {
		return nil, err
	}
	var cabecalho []string
	var lista []TarefaAgendada
	for _, linha := range registros {
		if len(linha) < 3 {
			continue
		}
		if cabecalho == nil || strings.EqualFold(strings.TrimSpace(linha[0]), "HostName") || strings.EqualFold(strings.TrimSpace(linha[0]), "Nome do host") {
			cabecalho = linha
			continue
		}
		t := TarefaAgendada{}
		for i, campo := range linha {
			if i >= len(cabecalho) {
				break
			}
			chave := strings.ToLower(strings.TrimSpace(cabecalho[i]))
			valor := strings.TrimSpace(campo)
			switch {
			case strings.Contains(chave, "taskname"), strings.Contains(chave, "nome da tarefa"):
				t.Nome = valor
			case strings.Contains(chave, "task to run"), strings.Contains(chave, "tarefa a ser executada"):
				t.Comando = valor
			case strings.Contains(chave, "author"), strings.Contains(chave, "autor"):
				t.Autor = valor
			case strings.Contains(chave, "status"), strings.Contains(chave, "status da"):
				if t.Estado == "" {
					t.Estado = valor
				}
			case strings.Contains(chave, "next run"), strings.Contains(chave, "proxima execucao"):
				t.Proxima = valor
			}
		}
		if t.Nome != "" && !strings.EqualFold(t.Comando, "N/A") {
			lista = append(lista, t)
		}
	}
	return lista, nil
}

func checarTarefasAgendadas(c *Contexto) {
	r := c.R
	r.Progresso("Lendo as tarefas agendadas do Windows")
	tarefas, err := lerTarefasAgendadas()
	if err != nil {
		r.Erro("listar tarefas agendadas: %v", err)
		return
	}
	r.Linha("%d tarefas agendadas cadastradas no Windows", len(tarefas))
	sinais := avaliarTarefas(tarefas, c.A)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) == 0 {
		r.Ok("Nenhuma tarefa agendada apontando para cheat, limpeza de rastros ou pasta suspeita")
	}
}

func checarStreamsOcultos(c *Contexto) {
	r := c.R
	var pastas []string
	for _, p := range c.Perfis {
		for _, sub := range []string{"Desktop", "Downloads", "Documents", "Videos", filepath.Join("AppData", "Local", "Temp"), filepath.Join("AppData", "Roaming")} {
			pastas = append(pastas, filepath.Join(p.Pasta, sub))
		}
	}
	pastas = append(pastas, `C:\Users\Public`, `C:\ProgramData`)
	for _, u := range unidadesFixas() {
		if !strings.EqualFold(u, `C:\`) {
			pastas = append(pastas, u)
		}
	}
	var streams []StreamOculto
	arquivos := 0
	interrompido := false
	inicio := time.Now()
	for _, pasta := range pastas {
		if !existe(pasta) {
			continue
		}
		filepath.WalkDir(pasta, func(caminho string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if estourouOTempo(inicio, c.LimiteEtapa) || c.DevePular() {
				interrompido = true
				return filepath.SkipAll
			}
			if d.IsDir() {
				if caminho != pasta && ignorarNoConteudo(caminho+string(os.PathSeparator), c.A) {
					return filepath.SkipDir
				}
				return nil
			}
			arquivos++
			if arquivos%5000 == 0 {
				r.Progresso("%d arquivos conferidos atras de fluxos alternativos (ADS)", arquivos)
			}
			streams = append(streams, streamsAlternativos(caminho)...)
			return nil
		})
	}
	r.Linha("Fluxos alternativos: %d arquivos conferidos em %s", arquivos, time.Since(inicio).Round(time.Second))
	if interrompido && !c.Pulou() {
		r.Add(Alerta, "LEITURA DE FLUXOS ALTERNATIVOS INCOMPLETA: parou por tempo", "Parte dos arquivos nao foi conferida. Rode de novo sem limite")
	}
	sinais := avaliarStreamsOcultos(streams, c.A)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) == 0 {
		r.Ok("Nenhum arquivo escondido em fluxo alternativo (ADS)")
	}
}

func checarVarreduraManual(c *Contexto) {
	r := c.R
	r.Secao("VARREDURA MANUAL (journal do disco, tarefas agendadas, arquivos escondidos)")
	checarTarefasAgendadas(c)
	if c.Rapido {
		r.Linha("Modo rapido: journal do NTFS e fluxos alternativos pulados")
		return
	}
	checarJournalDoDisco(c)
	checarStreamsOcultos(c)
}

func buscaLivre(c *Contexto, termo string) ResultadoBuscaLivre {
	res := ResultadoBuscaLivre{Termo: termo}
	buscador := NovoBuscador([]string{termo})
	alvo := strings.ToLower(termo)

	var raizes []string
	for _, p := range c.Perfis {
		raizes = append(raizes, p.Pasta)
	}
	for _, u := range unidadesFixas() {
		raizes = append(raizes, u)
	}
	vistos := map[string]bool{}
	for _, raiz := range raizes {
		filepath.WalkDir(raiz, func(caminho string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if len(res.Arquivos) > 3000 {
				return filepath.SkipAll
			}
			lower := strings.ToLower(caminho)
			if vistos[lower] {
				return nil
			}
			vistos[lower] = true
			if d.IsDir() {
				if ignorarNoConteudo(caminho+string(os.PathSeparator), c.A) {
					return filepath.SkipDir
				}
				if strings.Contains(strings.ToLower(d.Name()), alvo) {
					res.Arquivos = append(res.Arquivos, "[pasta] "+caminho)
					res.Total++
				}
				return nil
			}
			if strings.Contains(strings.ToLower(d.Name()), alvo) {
				info, _ := d.Info()
				linha := caminho
				if info != nil {
					linha = fmt.Sprintf("%s  (%d KB, %s)", caminho, info.Size()/1024, formataHora(info.ModTime()))
				}
				res.Arquivos = append(res.Arquivos, linha)
				res.Total++
				return nil
			}
			ext := strings.ToLower(filepath.Ext(caminho))
			if extensoesIgnoradasNoConteudo[ext] || extensoesDeImagemOuMidia[ext] {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() == 0 || info.Size() > 30*1024*1024 {
				return nil
			}
			dados, err := os.ReadFile(caminho)
			if err != nil {
				return nil
			}
			buscador.Procurar(dados, func(o Ocorrencia) bool {
				res.Arquivos = append(res.Arquivos, fmt.Sprintf("%s  [dentro do arquivo] ...%s...", caminho, trechoEmVolta(dados, o.Inicio, o.Fim, o.UTF16)))
				res.Total++
				return false
			})
			return nil
		})
	}

	for _, p := range c.Perfis {
		if !p.Hive {
			continue
		}
		for _, chave := range []string{
			`\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`,
			`\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`,
			`\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`,
			`\Software\Microsoft\Windows\CurrentVersion\Run`,
		} {
			for _, v := range valoresDaChave(registry.USERS, p.SID+chave) {
				texto := v.Nome + " " + v.Texto + " " + utf16DeBytes(v.Bytes)
				if strings.Contains(strings.ToLower(texto), alvo) {
					res.Registro = append(res.Registro, p.Usuario+chave+" -> "+resumeTexto(texto, 160))
					res.Total++
				}
			}
		}
	}

	processos, _ := listarProcessos()
	for _, p := range processos {
		nome := strings.ToLower(p.Nome)
		if strings.HasPrefix(nome, "scanner") || strings.HasPrefix(nome, "scanner") {
			continue
		}
		if !strings.HasPrefix(nome, "fivem") || !strings.Contains(nome, "gtaprocess") {
			continue
		}
		varrerMemoriaExecutavel(p.PID, 256*1024*1024, func(regiao RegiaoDeMemoria, dados []byte) {
			if len(res.Memoria) > 20 {
				return
			}
			buscador.Procurar(dados, func(o Ocorrencia) bool {
				res.Memoria = append(res.Memoria, fmt.Sprintf("%s (PID %d) 0x%X: ...%s...", p.Nome, p.PID, regiao.Base, trechoEmVolta(dados, o.Inicio, o.Fim, o.UTF16)))
				res.Total++
				return false
			})
		})
	}

	for _, unidade := range unidadesFixas() {
		letra := strings.TrimSuffix(unidade, `\`)
		var eventos []EventoUSN
		executarStream(45*time.Second, func(saida io.Reader) error {
			var err error
			eventos, _, err = lerUSNCsv(saida, 3000000, func(nome string) bool {
				return strings.Contains(strings.ToLower(nome), alvo)
			})
			return err
		}, "fsutil", "usn", "readjournal", letra, "csv")
		vistosUSN := map[string]bool{}
		for _, e := range eventos {
			chave := e.Nome + e.Motivo
			if vistosUSN[chave] || len(res.Journal) > 60 {
				continue
			}
			vistosUSN[chave] = true
			res.Journal = append(res.Journal, fmt.Sprintf("%s  %s  %s  (%s)", letra, formataHora(e.Hora), e.Nome, e.Motivo))
			res.Total++
		}
	}
	return res
}

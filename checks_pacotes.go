//go:build windows

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func abrirPacote(caminho string) PacoteAnalisado {
	p := PacoteAnalisado{Caminho: caminho, Formato: ehPacote(caminho)}
	info, err := os.Stat(caminho)
	if err != nil {
		p.Erro = err.Error()
		return p
	}
	p.Tamanho = info.Size()
	p.Modificado = info.ModTime()
	if p.Tamanho > 8*1024*1024*1024 {
		p.Erro = "pacote maior que 8 GB, aberto so parcialmente"
	}

	if p.Formato == "zip" {
		f, err := os.Open(caminho)
		if err != nil {
			p.Erro = err.Error()
			return p
		}
		defer f.Close()
		itens, truncado, err := lerZip(f, p.Tamanho, 3000)
		if err != nil {
			p.Erro = "arquivo zip invalido ou protegido por senha: " + err.Error()
			return p
		}
		p.Itens, p.Truncado = itens, truncado
		return p
	}

	if itens := listarComFerramentaExterna(caminho); len(itens) > 0 {
		p.Itens = itens
		return p
	}

	dados, err := os.ReadFile(caminho)
	if err != nil {
		p.Erro = err.Error()
		return p
	}
	limite := len(dados)
	if limite > 64*1024*1024 {
		limite = 64 * 1024 * 1024
		p.Truncado = true
	}
	p.Itens = nomesDentroDoRarPorTexto(dados[:limite], 3000)
	if len(p.Itens) == 0 {
		p.Erro = "nao consegui ler a lista de arquivos deste formato"
	}
	return p
}

func listarComFerramentaExterna(caminho string) []ItemDePacote {
	candidatos := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "7-Zip", "7z.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "7-Zip", "7z.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "WinRAR", "UnRAR.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "WinRAR", "UnRAR.exe"),
	}
	for _, ferramenta := range candidatos {
		if !existe(ferramenta) {
			continue
		}
		ehUnrar := strings.Contains(strings.ToLower(ferramenta), "unrar")
		var saida string
		var err error
		if ehUnrar {
			saida, err = executar(ferramenta, "l", "-idq", caminho)
		} else {
			saida, err = executar(ferramenta, "l", "-ba", "-slt", caminho)
		}
		if err != nil && saida == "" {
			continue
		}
		itens := lerListagemDePacote(paraUTF8(saida), ehUnrar, 3000)
		if len(itens) > 0 {
			return itens
		}
	}
	return nil
}

func pacoteInteressa(c *Contexto, caminho string, info fs.FileInfo) bool {
	nome := nomeBase(caminho)
	if ehPacote(nome) == "" {
		return false
	}
	if arquivoDoProprioJogo(caminho) || pacoteDeDriverOuInstalador(caminho) || conteudoInternoDaCitizen(nome) {
		return false
	}
	if c.A.Marca(nome) != "" || arquivoDoUniversoDoJogo(nome) != "" {
		return true
	}
	if classe, _ := c.A.Classificar(nome); classe != SemMatch && !c.A.TextoInocente(nome) {
		return true
	}
	if c.A.PalavraWeb(nome) != "" {
		return true
	}
	return pastaQuente(caminho) && time.Since(info.ModTime()) < 90*24*time.Hour && info.Size() < 500*1024*1024
}

func checarPacotes(c *Contexto) {
	r := c.R
	r.Secao("CONTEUDO DOS PACOTES BAIXADOS (zip, rar, 7z)")

	var pastas []string
	for _, p := range c.Perfis {
		for _, sub := range []string{"Downloads", "Desktop", "Documents", filepath.Join("AppData", "Local", "Temp")} {
			pastas = append(pastas, filepath.Join(p.Pasta, sub))
		}
	}
	pastas = append(pastas, `C:\Users\Public\Downloads`)
	for _, u := range unidadesFixas() {
		pastas = append(pastas, filepath.Join(u, "Downloads"))
	}

	var candidatos []string
	vistos := map[string]bool{}
	for _, pasta := range pastas {
		if !existe(pasta) {
			continue
		}
		filepath.WalkDir(pasta, func(caminho string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || len(candidatos) >= 400 {
				return nil
			}
			lower := strings.ToLower(caminho)
			if vistos[lower] {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if pacoteInteressa(c, caminho, info) {
				vistos[lower] = true
				candidatos = append(candidatos, caminho)
			}
			return nil
		})
	}
	sort.Strings(candidatos)
	r.Linha("%d pacote(s) compactado(s) para abrir e conferir por dentro", len(candidatos))
	if len(candidatos) == 0 {
		r.Ok("Nenhum pacote compactado suspeito nas pastas de download")
		return
	}

	achouAlgo := false
	for i, caminho := range candidatos {
		if c.DevePular() {
			r.Linha("Parei no pacote %d de %d a pedido", i+1, len(candidatos))
			break
		}
		r.Progresso("Abrindo pacote %d de %d: %s", i+1, len(candidatos), nomeBase(caminho))
		pacote := abrirPacote(caminho)
		sinais := avaliarPacote(pacote, c.A)
		for _, s := range sinais {
			if s.Severidade != Info {
				achouAlgo = true
			}
			r.Add(s.Severidade, s.Titulo, s.Detalhe)
		}
	}
	if !achouAlgo && !c.Pulou() {
		r.Ok("Nenhum programa, dll ou script escondido dentro dos pacotes conferidos")
	}
}

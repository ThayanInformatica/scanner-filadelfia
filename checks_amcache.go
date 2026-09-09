//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const chaveAmcacheTemporaria = `ScannerAmcache`

func carregarHiveDoAmcache(r *Relatorio) (func(), error) {
	original := filepath.Join(os.Getenv("SystemRoot"), "appcompat", "Programs", "Amcache.hve")
	if _, err := os.Stat(original); err != nil {
		return nil, err
	}
	executar("reg", "unload", `HKLM\`+chaveAmcacheTemporaria)
	if _, err := executar("reg", "load", `HKLM\`+chaveAmcacheTemporaria, original); err == nil {
		return func() { executar("reg", "unload", `HKLM\`+chaveAmcacheTemporaria) }, nil
	}
	r.Progresso("Amcache em uso pelo Windows, copiando para leitura")
	pasta, err := os.MkdirTemp("", "scanner-amcache-")
	if err != nil {
		return nil, err
	}
	copia := filepath.Join(pasta, "Amcache.hve")
	if err := copiarArquivoAberto(original, copia); err != nil {
		os.RemoveAll(pasta)
		return nil, err
	}
	if saida, err := executar("reg", "load", `HKLM\`+chaveAmcacheTemporaria, copia); err != nil {
		os.RemoveAll(pasta)
		return nil, errComTexto("reg load da copia", err, saida)
	}
	return func() {
		executar("reg", "unload", `HKLM\`+chaveAmcacheTemporaria)
		os.RemoveAll(pasta)
	}, nil
}

func lerAmcache(r *Relatorio) ([]EntradaAmcache, error) {
	descarregar, err := carregarHiveDoAmcache(r)
	if err != nil {
		return nil, err
	}
	defer descarregar()

	var entradas []EntradaAmcache
	raizNova := chaveAmcacheTemporaria + `\Root\InventoryApplicationFile`
	for _, sub := range subchaves(registry.LOCAL_MACHINE, raizNova) {
		chave := raizNova + `\` + sub
		caminho, _ := lerString(registry.LOCAL_MACHINE, chave, "LowerCaseLongPath")
		if caminho == "" {
			continue
		}
		e := EntradaAmcache{Caminho: caminho, Fonte: "InventoryApplicationFile"}
		e.Nome, _ = lerString(registry.LOCAL_MACHINE, chave, "Name")
		e.Editor, _ = lerString(registry.LOCAL_MACHINE, chave, "Publisher")
		e.Produto, _ = lerString(registry.LOCAL_MACHINE, chave, "ProductName")
		if id, ok := lerString(registry.LOCAL_MACHINE, chave, "FileId"); ok {
			e.SHA1 = strings.ToLower(strings.TrimPrefix(id, "0000"))
		}
		if tam, ok := lerString(registry.LOCAL_MACHINE, chave, "Size"); ok {
			e.Tamanho, _ = strconv.ParseInt(tam, 10, 64)
		} else if tam, ok := lerDword(registry.LOCAL_MACHINE, chave, "Size"); ok {
			e.Tamanho = int64(tam)
		}
		_, errStat := os.Stat(caminho)
		e.ExisteNoDisco = errStat == nil
		entradas = append(entradas, e)
	}

	raizAntiga := chaveAmcacheTemporaria + `\Root\File`
	for _, volume := range subchaves(registry.LOCAL_MACHINE, raizAntiga) {
		for _, id := range subchaves(registry.LOCAL_MACHINE, raizAntiga+`\`+volume) {
			chave := raizAntiga + `\` + volume + `\` + id
			caminho, _ := lerString(registry.LOCAL_MACHINE, chave, "15")
			if caminho == "" {
				continue
			}
			e := EntradaAmcache{Caminho: caminho, Fonte: "File"}
			if h, ok := lerString(registry.LOCAL_MACHINE, chave, "101"); ok {
				e.SHA1 = strings.ToLower(strings.TrimPrefix(h, "0000"))
			}
			e.Produto, _ = lerString(registry.LOCAL_MACHINE, chave, "0")
			e.Editor, _ = lerString(registry.LOCAL_MACHINE, chave, "1")
			_, errStat := os.Stat(caminho)
			e.ExisteNoDisco = errStat == nil
			entradas = append(entradas, e)
		}
	}
	return entradas, nil
}

func checarAmcache(c *Contexto) {
	r := c.R
	r.Secao("AMCACHE (programas que ja executaram, com hash)")
	r.Progresso("Carregando o Amcache.hve do Windows")
	entradas, err := lerAmcache(r)
	if err != nil {
		r.Erro("ler Amcache: %v", err)
		r.Add(Alerta, "AMCACHE NAO PODE SER LIDO", "O Windows nao deixou carregar o Amcache.hve. Sem ele, fica de fora o registro de programas executados com hash, que e o artefato que mais resiste a limpeza.\n"+err.Error())
		return
	}
	r.Linha("%d entradas no Amcache", len(entradas))
	c.Rastros.AmcacheLido = true
	c.Rastros.AmcacheQuantidade = len(entradas)
	sinais := avaliarAmcache(entradas, c.A)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) <= 1 {
		r.Ok("Nenhum programa com nome ou hash de cheat no historico de execucao do Amcache")
	}
}

func copiarArquivoAberto(origem, destino string) error {
	src, err := os.Open(origem)
	if err == nil {
		defer src.Close()
		dst, errDst := os.Create(destino)
		if errDst != nil {
			return errDst
		}
		defer dst.Close()
		if _, errCopia := io.Copy(dst, src); errCopia == nil {
			return nil
		}
	}
	saida, errVss := executar("esentutl", "/y", origem, "/vss", "/d", destino)
	if errVss != nil {
		return errComTexto("copiar arquivo em uso (esentutl /vss)", errVss, saida)
	}
	return nil
}

func errComTexto(contexto string, err error, saida string) error {
	return fmt.Errorf("%s: %v %s", contexto, err, resume(paraUTF8(saida), 200))
}

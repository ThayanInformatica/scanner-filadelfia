//go:build !windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const suportaChecagemReal = false

func etapasDoSistema() []Etapa {
	return []Etapa{
		{"Checagem real (somente Windows)", func(c *Contexto) {
			c.R.Secao("PLATAFORMA")
			c.R.Add(Alerta, "Este binario nao foi compilado para Windows", "As checagens de registro, servicos, logs, drivers e Prefetch so existem na versao windows/amd64. Use o modo simulado para conferir a interface")
		}, false},
	}
}

func unidadesFixas() []string { return nil }

func preencherPerfis(c *Contexto) {}

func buscaLivre(c *Contexto, termo string) ResultadoBuscaLivre {
	return ResultadoBuscaLivre{Termo: termo, Arquivos: []string{"A busca livre so funciona na versao Windows do scanner"}}
}

func estaElevado() bool { return true }

func relancarElevado() error { return nil }

func habilitarCoresConsole() bool { return true }

func abrirNoSistema(alvo string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("open", alvo).Start()
	}
	return exec.Command("xdg-open", alvo).Start()
}

func selecionarNoExplorer(caminho string) error {
	return abrirNoSistema(filepath.Dir(caminho))
}

func marcasDoHardware() string {
	nome, _ := os.Hostname()
	return "outros|" + nome
}

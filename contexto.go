package main

import (
	"sync/atomic"
	"time"
)

type Contexto struct {
	R           *Relatorio
	A           *Assinaturas
	Perfis      []Perfil
	Instalacao  time.Time
	Boot        time.Time
	Rapido      bool
	Verboso     bool
	LimiteEtapa time.Duration
	pular       atomic.Bool
	pulou       atomic.Bool

	SysMainDesativado      bool
	JogoFechado            bool
	JogoAbriuEm            time.Time
	TaskmgrAbertoEm        time.Time
	Execucoes              []EventoDeExecucao
	AssinaturasDeProcessos map[string][2]string
	Rastros                RastrosDeExecucao
	AoVivo                 ConferidoAoVivo
}

func (c *Contexto) PedirParaPular() {
	c.pular.Store(true)
}

func (c *Contexto) ComecaEtapa() {
	c.pular.Store(false)
	c.pulou.Store(false)
}

func (c *Contexto) DevePular() bool {
	if c.pular.Load() {
		c.pulou.Store(true)
		return true
	}
	return false
}

func (c *Contexto) Pulou() bool {
	return c.pulou.Load()
}

func (c *Contexto) RegistraExecucao(caminho string, quando time.Time, fonte string) {
	if caminho == "" {
		return
	}
	c.Execucoes = append(c.Execucoes, EventoDeExecucao{Caminho: caminho, Quando: quando, Fonte: fonte})
}

type Perfil struct {
	SID     string
	Pasta   string
	Usuario string
	Hive    bool
}

type Etapa struct {
	Nome   string
	Fn     func(*Contexto)
	Pesada bool
}

func formataHora(t time.Time) string {
	if t.IsZero() {
		return "desconhecido"
	}
	return t.Format("02/01/2006 15:04:05")
}

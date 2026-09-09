//go:build windows

package main

import "time"

func checarRastrosDeExecucao(c *Contexto) {
	r := c.R
	r.Secao("RASTROS DE EXECUCAO (o PC ainda registra o que rodou?)")
	c.Rastros.SysMainDesativado = c.SysMainDesativado
	sinais := avaliarRastrosDeExecucao(c.Rastros, c.Instalacao, time.Now())
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) == 0 {
		r.Ok("Prefetch, BAM, Amcache, ShimCache, logs e journal estao registrando normalmente: o que rodou neste PC deixou rastro")
	}
}

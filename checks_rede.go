//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var reHex64 = regexp.MustCompile(`0x([0-9a-fA-F]{16})`)

func checarRede(c *Contexto) {
	r := c.R
	r.Secao("CACHE DNS (sites acessados desde o boot)")

	saida, err := executar("ipconfig", "/displaydns")
	if err != nil {
		r.Erro("ipconfig /displaydns: %v", err)
	} else {
		vistos := map[string]bool{}
		total := 0
		for _, l := range strings.Split(saida, "\n") {
			l = strings.TrimSpace(l)
			if !strings.Contains(l, ":") {
				continue
			}
			partes := strings.SplitN(l, ":", 2)
			valor := strings.TrimSpace(partes[1])
			if valor == "" || strings.ContainsAny(valor, " ") {
				continue
			}
			if !strings.Contains(valor, ".") || strings.HasPrefix(valor, "0x") || net.ParseIP(valor) != nil {
				continue
			}
			dominio := strings.ToLower(valor)
			if vistos[dominio] {
				continue
			}
			vistos[dominio] = true
			total++
			if t := c.A.Dominio(dominio); t != "" {
				r.Add(Critico, "Cache DNS tem dominio de cheat ('"+t+"'): "+dominio, "O PC resolveu esse dominio desde o ultimo boot")
			}
		}
		r.Linha("%d nomes unicos no cache DNS", total)
		if total < 5 && tempoLigado() > 3*time.Hour {
			c.Rastros.DNSVazio = true
		}
		if total < 5 && tempoLigado() > 30*time.Minute {
			r.Add(Alerta, "Cache DNS praticamente vazio com o PC ligado ha mais de 30 min", "ipconfig /flushdns ou servico Dnscache parado")
		}
	}

	r.Secao("JOURNAL USN (historico de alteracoes do disco)")
	for _, unidade := range unidadesFixas() {
		letra := strings.TrimSuffix(unidade, `\`)
		saida, err := executar("fsutil", "usn", "queryjournal", letra)
		if err != nil {
			r.Add(Alerta, "Unidade "+letra+" SEM journal USN", "fsutil usn deletejournal apaga o historico de arquivos criados/apagados. O Windows recria o journal sozinho depois")
			continue
		}
		m := reHex64.FindStringSubmatch(saida)
		if m == nil {
			nota := "fsutil usn deletejournal apaga o historico de arquivos criados/apagados. "
			if !strings.EqualFold(strings.TrimSuffix(letra, ":"), strings.TrimSuffix(os.Getenv("SystemDrive"), ":")) {
				nota = "Em disco de dados o journal so existe se o Windows Search ou algum programa criou; pode nunca ter existido. Mas fsutil usn deletejournal e o jeito de apagar o historico de arquivos criados/apagados, e o disco de jogos e onde o cheat costuma ficar. "
			}
			r.Add(Alerta, "Unidade "+letra+" sem journal USN ativo", nota+"Resposta: "+resume(saida, 200))
			continue
		}
		id, _ := strconv.ParseUint(m[1], 16, 64)
		criado := filetimeParaTime(id)
		r.Linha("%s: journal criado em %s", letra, formataHora(criado))
		if criado.IsZero() {
			continue
		}
		if !c.Instalacao.IsZero() && criado.Sub(c.Instalacao) > 24*time.Hour && time.Since(criado) < 14*24*time.Hour {
			c.Rastros.JournalRecriado = append(c.Rastros.JournalRecriado, letra)
			r.Add(Alerta, fmt.Sprintf("Journal USN de %s foi recriado em %s", letra, formataHora(criado)), fmt.Sprintf("Windows instalado em %s. Journal recriado depois da instalacao indica 'fsutil usn deletejournal' (ou chkdsk/erro de disco)", formataHora(c.Instalacao)))
		}
	}
}

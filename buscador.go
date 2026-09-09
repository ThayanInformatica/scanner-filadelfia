package main

import (
	"strings"
	"unicode/utf16"
)

type padraoBusca struct {
	termo string
	bytes []byte
	utf16 bool
	curto bool
}

type Buscador struct {
	transicoes [][256]int32
	falha      []int32
	saidas     [][]int32
	padroes    []padraoBusca
}

func NovoBuscador(termos []string) *Buscador {
	b := &Buscador{}
	b.transicoes = append(b.transicoes, [256]int32{})
	b.saidas = append(b.saidas, nil)
	vistos := map[string]bool{}
	for _, t := range termos {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || vistos[t] {
			continue
		}
		vistos[t] = true
		b.adiciona(padraoBusca{termo: t, bytes: []byte(t), curto: true})
		b.adiciona(padraoBusca{termo: t, bytes: utf16LE(t), utf16: true, curto: true})
	}
	b.constroiFalhas()
	return b
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	saida := make([]byte, 0, len(u)*2)
	for _, c := range u {
		saida = append(saida, byte(c), byte(c>>8))
	}
	return saida
}

func (b *Buscador) adiciona(p padraoBusca) {
	no := int32(0)
	for _, c := range p.bytes {
		prox := b.transicoes[no][c]
		if prox == 0 {
			b.transicoes = append(b.transicoes, [256]int32{})
			b.saidas = append(b.saidas, nil)
			prox = int32(len(b.transicoes) - 1)
			b.transicoes[no][c] = prox
		}
		no = prox
	}
	b.padroes = append(b.padroes, p)
	b.saidas[no] = append(b.saidas[no], int32(len(b.padroes)-1))
}

func (b *Buscador) constroiFalhas() {
	b.falha = make([]int32, len(b.transicoes))
	var fila []int32
	for c := 0; c < 256; c++ {
		if filho := b.transicoes[0][c]; filho != 0 {
			fila = append(fila, filho)
		}
	}
	for len(fila) > 0 {
		atual := fila[0]
		fila = fila[1:]
		for c := 0; c < 256; c++ {
			filho := b.transicoes[atual][c]
			if filho == 0 {
				b.transicoes[atual][c] = b.transicoes[b.falha[atual]][c]
				continue
			}
			fila = append(fila, filho)
			f := b.falha[atual]
			for f != 0 && b.transicoes[f][c] == 0 {
				f = b.falha[f]
			}
			b.falha[filho] = b.transicoes[f][c]
			b.saidas[filho] = append(b.saidas[filho], b.saidas[b.falha[filho]]...)
		}
	}
}

func minusculaByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func alfanumericoByte(c byte) bool {
	c = minusculaByte(c)
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func legivelByte(c byte) bool {
	return (c >= 0x20 && c <= 0x7e) || c == 0 || c == '\n' || c == '\r' || c == '\t'
}

func (b *Buscador) respeitaBorda(dados []byte, inicio, fim int, p padraoBusca) bool {
	passo := 1
	if p.utf16 {
		passo = 2
	}
	if inicio-passo >= 0 && alfanumericoByte(dados[inicio-passo]) {
		return false
	}
	depois := fim
	if depois < len(dados) && minusculaByte(dados[depois]) == 's' {
		depois += passo
	}
	if depois < len(dados) && alfanumericoByte(dados[depois]) {
		return false
	}
	for i := 1; i <= 3; i++ {
		if inicio-i*passo >= 0 && !legivelByte(dados[inicio-i*passo]) {
			return false
		}
		if depois+(i-1)*passo < len(dados) && !legivelByte(dados[depois+(i-1)*passo]) {
			return false
		}
	}
	return true
}

type Ocorrencia struct {
	Termo  string
	Inicio int
	Fim    int
	UTF16  bool
}

func (b *Buscador) Procurar(dados []byte, fn func(o Ocorrencia) bool) {
	no := int32(0)
	for i, c := range dados {
		no = b.transicoes[no][minusculaByte(c)]
		if len(b.saidas[no]) == 0 {
			continue
		}
		for _, idx := range b.saidas[no] {
			p := b.padroes[idx]
			inicio := i + 1 - len(p.bytes)
			if !b.respeitaBorda(dados, inicio, i+1, p) {
				continue
			}
			if !fn(Ocorrencia{Termo: p.termo, Inicio: inicio, Fim: i + 1, UTF16: p.utf16}) {
				return
			}
		}
	}
}

func ehCaractereDeURL(c byte) bool {
	if alfanumericoByte(c) {
		return true
	}
	return strings.IndexByte("-._~:/?#@!$&'()*+,;=%", c) >= 0
}

func urlEmVolta(dados []byte, inicio, fim int) string {
	i := inicio
	for i > 0 && ehCaractereDeURL(dados[i-1]) {
		i--
	}
	f := fim
	for f < len(dados) && ehCaractereDeURL(dados[f]) {
		f++
	}
	u := string(dados[i:f])
	u = strings.TrimRight(u, ".,;:)'\"")
	if strings.Contains(u, "://") || strings.HasPrefix(u, "www.") {
		if idx := strings.Index(u, "://"); idx > 0 {
			ini := idx
			for ini > 0 && (alfanumericoByte(u[ini-1]) || u[ini-1] == '+' || u[ini-1] == '-' || u[ini-1] == '.') {
				ini--
			}
			u = u[ini:]
		}
		return u
	}
	return ""
}

func trechoEmVolta(dados []byte, inicio, fim int, utf16 bool) string {
	raio := 70
	if utf16 {
		raio = 140
	}
	i := inicio - raio
	if i < 0 {
		i = 0
	}
	f := fim + raio
	if f > len(dados) {
		f = len(dados)
	}
	pedaco := dados[i:f]
	var sb strings.Builder
	ultimoEspaco := true
	for _, c := range pedaco {
		if utf16 && c == 0 {
			continue
		}
		if c < 0x20 || c == 0x7f || c > 0x7e {
			c = ' '
		}
		if c == ' ' {
			if ultimoEspaco {
				continue
			}
			ultimoEspaco = true
		} else {
			ultimoEspaco = false
		}
		sb.WriteByte(c)
	}
	return strings.TrimSpace(sb.String())
}

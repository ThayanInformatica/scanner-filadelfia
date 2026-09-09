//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

type entradaShimCache struct {
	Caminho    string
	Modificado time.Time
}

func lerShimCache() ([]entradaShimCache, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	dados, _, err := k.GetBinaryValue("AppCompatCache")
	if err != nil {
		return nil, err
	}
	if len(dados) < 48 {
		return nil, fmt.Errorf("cache pequeno demais (%d bytes)", len(dados))
	}
	inicio := int(binary.LittleEndian.Uint32(dados[:4]))
	if inicio <= 0 || inicio >= len(dados) {
		inicio = 48
	}
	var lista []entradaShimCache
	off := inicio
	for off+12 <= len(dados) && len(lista) < 2000 {
		assinatura := string(dados[off : off+4])
		if assinatura != "10ts" && assinatura != "00ts" && assinatura != "11ts" {
			off++
			continue
		}
		if off+12 > len(dados) {
			break
		}
		tamEntrada := int(binary.LittleEndian.Uint32(dados[off+8 : off+12]))
		p := off + 12
		if tamEntrada <= 0 || p+2 > len(dados) {
			break
		}
		tamCaminho := int(binary.LittleEndian.Uint16(dados[p : p+2]))
		p += 2
		if tamCaminho < 0 || p+tamCaminho > len(dados) {
			break
		}
		caminho := utf16DeBytes(dados[p : p+tamCaminho])
		p += tamCaminho
		hora := time.Time{}
		if p+8 <= len(dados) {
			hora = filetimeDeBytes(dados[p : p+8])
		}
		if caminho != "" {
			lista = append(lista, entradaShimCache{Caminho: caminho, Modificado: hora})
		}
		prox := off + 12 + tamEntrada
		if prox <= off || prox > len(dados) {
			break
		}
		off = prox
	}
	return lista, nil
}

func checarShimCache(c *Contexto) {
	r := c.R
	entradas, err := lerShimCache()
	if err != nil {
		r.Erro("ler AppCompatCache: %v", err)
		return
	}
	r.Linha("AppCompatCache (ShimCache): %d executaveis registrados pelo Windows", len(entradas))
	if len(entradas) == 0 {
		r.Add(Alerta, "ShimCache vazio", "O AppCompatCache guarda executaveis vistos pelo Windows e so e reescrito no desligamento. Vazio indica limpeza direta no registro")
		return
	}
	achou := 0
	var suspeitos []string
	for _, e := range entradas {
		c.RegistraExecucao(e.Caminho, e.Modificado, "ShimCache")
		nome := filepath.Base(e.Caminho)
		if strings.HasPrefix(strings.ToLower(nome), "scanner") {
			continue
		}
		if classe, t := c.A.Classificar(e.Caminho); classe != SemMatch {
			achou++
			r.Add(classe.Severidade(), "ShimCache registrou execucao de arquivo com assinatura '"+t+"': "+nome, e.Caminho+"\nmodificado: "+formataHora(e.Modificado)+"\nO ShimCache guarda o caminho mesmo que o arquivo tenha sido apagado e o Prefetch limpo")
			continue
		}
		if motivo := caminhoSuspeito(e.Caminho); motivo != "" {
			suspeitos = append(suspeitos, formataHora(e.Modificado)+"  "+e.Caminho+"  ("+motivo+")")
		}
	}
	if len(suspeitos) > 0 {
		r.Add(Alerta, fmt.Sprintf("ShimCache tem %d executavel(is) de pasta suspeita", len(suspeitos)), strings.Join(limitaLinhas(suspeitos, 100), "\n"))
	}
	if achou == 0 && len(suspeitos) == 0 {
		r.Ok("Nenhum executavel de cheat no ShimCache")
	}
}

func checarRelatoriosDeErro(c *Contexto) {
	r := c.R
	pastas := []string{
		filepath.Join(os.Getenv("ProgramData"), "Microsoft", "Windows", "WER", "ReportArchive"),
		filepath.Join(os.Getenv("ProgramData"), "Microsoft", "Windows", "WER", "ReportQueue"),
	}
	for _, p := range c.Perfis {
		pastas = append(pastas, filepath.Join(p.Pasta, "AppData", "Local", "Microsoft", "Windows", "WER", "ReportArchive"))
		pastas = append(pastas, filepath.Join(p.Pasta, "AppData", "Local", "CrashDumps"))
	}
	total := 0
	achou := 0
	var recentes []string
	for _, pasta := range pastas {
		filepath.WalkDir(pasta, func(caminho string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			nome := strings.ToLower(d.Name())
			if nome != "report.wer" && !strings.HasSuffix(nome, ".dmp") {
				return nil
			}
			total++
			info, _ := d.Info()
			hora := time.Time{}
			if info != nil {
				hora = info.ModTime()
			}
			alvo := caminho
			if nome == "report.wer" {
				dados, err := os.ReadFile(caminho)
				if err != nil {
					return nil
				}
				texto := utf16DeBytes(dados)
				if !strings.Contains(texto, "=") {
					texto = string(dados)
				}
				for _, l := range strings.Split(texto, "\n") {
					l = strings.TrimSpace(l)
					if strings.HasPrefix(l, "AppPath=") || strings.HasPrefix(l, "TargetAppPath=") {
						alvo = strings.SplitN(l, "=", 2)[1]
					}
				}
			}
			if strings.HasPrefix(strings.ToLower(filepath.Base(alvo)), "scanner") {
				return nil
			}
			if classe, t := c.A.Classificar(alvo); classe != SemMatch {
				achou++
				r.Add(classe.Severidade(), "Relatorio de erro do Windows de um programa com assinatura '"+t+"'", alvo+"\n"+formataHora(hora)+"\nem: "+caminho+"\nO Windows guarda o crash mesmo depois do programa ser apagado. Cheat trava com frequencia e deixa esse rastro")
				return nil
			}
			if time.Since(hora) < 30*24*time.Hour && (pastaQuente(alvo) || !caminhoDoSistema(alvo)) {
				recentes = append(recentes, formataHora(hora)+"  "+alvo)
			}
			return nil
		})
	}
	r.Linha("Relatorios de erro e dumps do Windows: %d arquivos analisados", total)
	sort.Strings(recentes)
	if len(recentes) > 0 {
		r.Add(Info, fmt.Sprintf("Programas fora do Windows que travaram nos ultimos 30 dias: %d", len(recentes)), strings.Join(limitaLinhas(recentes, 100), "\n"))
	}
	if achou == 0 {
		r.Ok("Nenhum relatorio de erro de programa com nome de cheat")
	}
}

func checarAtalhosEJumpLists(c *Contexto) {
	r := c.R
	buscador := NovoBuscador(c.A.TermosParaConteudo())
	total := 0
	achou := 0
	for _, p := range c.Perfis {
		pastas := []string{
			filepath.Join(p.Pasta, "AppData", "Roaming", "Microsoft", "Windows", "Recent"),
			filepath.Join(p.Pasta, "AppData", "Roaming", "Microsoft", "Office", "Recent"),
			filepath.Join(p.Pasta, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu"),
			filepath.Join(p.Pasta, "Desktop"),
		}
		for _, pasta := range pastas {
			filepath.WalkDir(pasta, func(caminho string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(d.Name()))
				if ext != ".lnk" && !strings.Contains(strings.ToLower(d.Name()), "destinations-ms") {
					return nil
				}
				info, err := d.Info()
				if err != nil || info.Size() > 8*1024*1024 {
					return nil
				}
				dados, err := os.ReadFile(caminho)
				if err != nil {
					return nil
				}
				total++
				vistos := map[string]bool{}
				buscador.Procurar(dados, func(o Ocorrencia) bool {
					if vistos[o.Termo] {
						return true
					}
					vistos[o.Termo] = true
					achou++
					tipo := "Atalho (.lnk)"
					if ext != ".lnk" {
						tipo = "Jump List (arquivos recentes de um programa)"
					}
					r.Add(Critico, tipo+" aponta para arquivo com assinatura '"+o.Termo+"'", caminho+"\n"+formataHora(info.ModTime())+"\n..."+trechoEmVolta(dados, o.Inicio, o.Fim, o.UTF16)+"...\nO atalho guarda o caminho do arquivo original mesmo depois dele ser apagado")
					return len(vistos) < 4
				})
				return nil
			})
		}
	}
	r.Linha("Atalhos e jump lists analisados: %d", total)
	if achou == 0 {
		r.Ok("Nenhum atalho ou jump list apontando para cheat")
	}
}

func checarArtefatos(c *Contexto) {
	r := c.R
	r.Secao("ARTEFATOS DO WINDOWS (ShimCache, crashes, atalhos)")
	r.Progresso("Lendo o AppCompatCache do registro")
	checarShimCache(c)
	r.Progresso("Lendo relatorios de erro e dumps do Windows")
	checarRelatoriosDeErro(c)
	r.Progresso("Lendo atalhos e jump lists")
	checarAtalhosEJumpLists(c)
}

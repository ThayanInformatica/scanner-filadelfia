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
)

func checarPrefetch(c *Contexto) {
	r := c.R
	r.Secao("PREFETCH (programas executados)")

	pasta := filepath.Join(os.Getenv("SystemRoot"), "Prefetch")
	entradas, err := os.ReadDir(pasta)
	if err != nil {
		r.Erro("ler %s: %v", pasta, err)
		return
	}
	type pf struct {
		nome string
		hora time.Time
	}
	var arquivos []pf
	for _, e := range entradas {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".pf") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		arquivos = append(arquivos, pf{nome: e.Name(), hora: info.ModTime()})
	}
	sort.Slice(arquivos, func(i, j int) bool { return arquivos[i].hora.After(arquivos[j].hora) })
	r.Linha("%d arquivos .pf em %s", len(arquivos), pasta)

	if len(arquivos) == 0 && c.SysMainDesativado {
		r.Add(Alerta, "Pasta Prefetch vazia porque o SysMain esta desativado", "Sem SysMain o Windows nao grava .pf. Comum em tutorial de otimizacao de SSD, mas tambem e o jeito de nao deixar rastro de programa executado")
	} else if len(arquivos) == 0 {
		r.Add(Critico, "Pasta Prefetch VAZIA", "Prefetch limpo ou desativado. Windows em uso normal tem centenas de .pf")
	} else {
		maisAntigo := arquivos[len(arquivos)-1].hora
		r.Linha("Mais antigo: %s   Mais recente: %s", formataHora(maisAntigo), formataHora(arquivos[0].hora))
		if !c.Instalacao.IsZero() && time.Since(c.Instalacao) > 72*time.Hour && time.Since(maisAntigo) < 24*time.Hour {
			r.Add(Critico, "Prefetch foi LIMPO nas ultimas 24h", fmt.Sprintf("Todos os %d arquivos .pf sao posteriores a %s, mas o Windows foi instalado em %s", len(arquivos), formataHora(maisAntigo), formataHora(c.Instalacao)))
		} else if len(arquivos) < 40 && !c.Instalacao.IsZero() && time.Since(c.Instalacao) > 7*24*time.Hour {
			r.Add(Alerta, fmt.Sprintf("Prefetch com poucos arquivos (%d)", len(arquivos)), "Pode ter sido limpo parcialmente ou o SysMain ficou desligado")
		}
	}

	var recentes []string
	for _, a := range arquivos {
		c.RegistraExecucao(a.nome, a.hora, "Prefetch")
		nomeExe := a.nome
		if i := strings.LastIndex(nomeExe, "-"); i > 0 {
			nomeExe = nomeExe[:i]
		}
		if classe, t := c.A.Classificar(nomeExe); classe != SemMatch {
			r.Add(classe.Severidade(), "Prefetch de programa que bate com assinatura '"+t+"': "+nomeExe, "Ultima execucao: "+formataHora(a.hora)+"  ("+a.nome+")")
			continue
		}
		if pareceNomeAleatorio(nomeExe) {
			r.Add(Alerta, "Prefetch de executavel com nome aleatorio: "+nomeExe, "Ultima execucao: "+formataHora(a.hora))
			continue
		}
		if time.Since(a.hora) < 48*time.Hour && len(recentes) < 80 {
			recentes = append(recentes, formataHora(a.hora)+"  "+nomeExe)
		}
	}
	if len(recentes) > 0 {
		r.Add(Info, fmt.Sprintf("Programas executados nas ultimas 48h (Prefetch): %d", len(recentes)), strings.Join(limita(recentes, 240), "\n"))
	}
}

func checarRecentesELixeira(c *Contexto) {
	r := c.R
	r.Secao("ARQUIVOS RECENTES E LIXEIRA")

	for _, p := range c.Perfis {
		pasta := filepath.Join(p.Pasta, `AppData\Roaming\Microsoft\Windows\Recent`)
		entradas, err := os.ReadDir(pasta)
		if err != nil {
			continue
		}
		total := 0
		var maisNovo time.Time
		for _, e := range entradas {
			if e.IsDir() {
				continue
			}
			total++
			if info, err := e.Info(); err == nil && info.ModTime().After(maisNovo) {
				maisNovo = info.ModTime()
			}
			if classe, t := c.A.Classificar(e.Name()); classe != SemMatch {
				r.Add(classe.Severidade(), "Arquivo recente de "+p.Usuario+" bate com assinatura '"+t+"'", filepath.Join(pasta, e.Name()))
			}
		}
		r.Linha("Recentes de %s: %d atalhos, ultimo em %s", p.Usuario, total, formataHora(maisNovo))
		if total == 0 && !c.Instalacao.IsZero() && time.Since(c.Instalacao) > 72*time.Hour {
			r.Add(Alerta, "Pasta de recentes de "+p.Usuario+" esta vazia", "Limpeza manual ou por ferramenta (CCleaner e similares)")
		}
	}

	for _, unidade := range unidadesFixas() {
		raiz := filepath.Join(unidade, `$Recycle.Bin`)
		sids, err := os.ReadDir(raiz)
		if err != nil {
			continue
		}
		for _, s := range sids {
			if !s.IsDir() {
				continue
			}
			usuario := s.Name()
			for _, p := range c.Perfis {
				if strings.EqualFold(p.SID, s.Name()) {
					usuario = p.Usuario
				}
			}
			itens, err := os.ReadDir(filepath.Join(raiz, s.Name()))
			if err != nil {
				continue
			}
			total := 0
			var linhas []string
			for _, item := range itens {
				if !strings.HasPrefix(item.Name(), "$I") {
					continue
				}
				total++
				nomeOriginal, deletadoEm := lerMetadadoLixeira(filepath.Join(raiz, s.Name(), item.Name()))
				if nomeOriginal == "" {
					continue
				}
				if classe, t := c.A.Classificar(nomeOriginal); classe != SemMatch {
					sev := classe.Severidade()
					nota := ""
					if !deletadoEm.IsZero() && time.Since(deletadoEm) > 180*24*time.Hour {
						nota = "\nDeletado ha mais de 6 meses: mostra uso antigo, nao uso atual"
						if c.A.Marca(nomeOriginal) == "" && sev == Critico {
							sev = Alerta
						}
					}
					r.Add(sev, "Item na LIXEIRA de "+usuario+" bate com assinatura '"+t+"'", nomeOriginal+"  (deletado em "+formataHora(deletadoEm)+")"+nota)
					continue
				}
				ext := strings.ToLower(filepath.Ext(nomeOriginal))
				if ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".rar" || ext == ".zip" || ext == ".7z" || ext == ".bat" || ext == ".ps1" {
					linhas = append(linhas, formataHora(deletadoEm)+"  "+nomeOriginal)
				}
			}
			r.Linha("Lixeira de %s em %s: %d itens", usuario, unidade, total)
			if len(linhas) > 0 {
				r.Add(Info, fmt.Sprintf("Executaveis/arquivos compactados na lixeira de %s (%s)", usuario, unidade), strings.Join(limita(linhas, 120), "\n"))
			}
		}
	}
}

func lerMetadadoLixeira(caminho string) (string, time.Time) {
	b, err := os.ReadFile(caminho)
	if err != nil || len(b) < 24 {
		return "", time.Time{}
	}
	versao := binary.LittleEndian.Uint64(b[0:8])
	deletado := filetimeDeBytes(b[16:24])
	if versao == 2 && len(b) >= 28 {
		return utf16DeBytes(b[28:]), deletado
	}
	return utf16DeBytes(b[24:]), deletado
}

type arquivoAchado struct {
	Caminho string
	Hora    time.Time
	Tamanho int64
}

func checarArquivos(c *Contexto) {
	r := c.R
	r.Secao("VARREDURA DE ARQUIVOS")
	if c.Rapido {
		r.Linha("Modo rapido: varredura de disco pulada")
		return
	}

	var pastasQuentes, pastasNormais []string
	for _, p := range c.Perfis {
		for _, sub := range []string{"Desktop", "Downloads", "Documents", "Videos", "Pictures", "Music", `AppData\Local\Temp`, "OneDrive"} {
			pastasQuentes = append(pastasQuentes, filepath.Join(p.Pasta, sub))
		}
		pastasNormais = append(pastasNormais, filepath.Join(p.Pasta, `AppData\Local`), filepath.Join(p.Pasta, `AppData\Roaming`), filepath.Join(p.Pasta, `AppData\LocalLow`))
	}
	pastasQuentes = append(pastasQuentes, filepath.Join(os.Getenv("SystemRoot"), "Temp"), `C:\Users\Public`, `C:\Temp`, `C:\tmp`)
	pastasNormais = append(pastasNormais, `C:\ProgramData`, os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"))
	pastasNormais = append(pastasNormais, c.A.PastasExtra...)

	inicio := time.Now()
	limiteTempo := c.LimiteEtapa
	total := 0
	ultimoAviso := time.Now()
	var recentes []arquivoAchado
	var disfarcados []string
	vistos := map[string]bool{}

	visita := func(raiz string, profundidadeMax int, quente bool) {
		raiz = filepath.Clean(raiz)
		if raiz == "." || raiz == "" {
			return
		}
		if _, err := os.Stat(raiz); err != nil {
			return
		}
		base := strings.Count(raiz, string(os.PathSeparator))
		filepath.WalkDir(raiz, func(caminho string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if estourouOTempo(inicio, limiteTempo) || c.DevePular() {
				return filepath.SkipAll
			}
			lower := strings.ToLower(caminho)
			if d.IsDir() {
				nome := strings.ToLower(d.Name())
				if strings.Count(caminho, string(os.PathSeparator))-base >= profundidadeMax || nome == "node_modules" || nome == ".git" || nome == "winsxs" || nome == "windows" || nome == "program files" || nome == "program files (x86)" || nome == "$recycle.bin" || nome == "system volume information" || c.A.Ignorar(lower+`\`) {
					if caminho != raiz {
						return filepath.SkipDir
					}
				}
				if classe, t := c.A.Classificar(d.Name()); classe != SemMatch && !vistos[lower] {
					vistos[lower] = true
					r.Add(classe.Severidade(), "Pasta bate com assinatura '"+t+"'", caminho)
				}
				return nil
			}
			if vistos[lower] || c.A.Ignorar(lower) || ehOProprioScanner(caminho, 0) {
				return nil
			}
			vistos[lower] = true
			total++
			if time.Since(ultimoAviso) > 1500*time.Millisecond {
				ultimoAviso = time.Now()
				r.Progresso("%d arquivos vistos em %s. Agora em: %s", total, time.Since(inicio).Round(time.Second), filepath.Dir(caminho))
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if extensoesDeImagemOuMidia[ext] || extensaoDeTexto(d.Name()) {
				return nil
			}
			if classe, t := c.A.Classificar(d.Name()); classe != SemMatch {
				info, _ := d.Info()
				detalhe := caminho
				if info != nil {
					detalhe += fmt.Sprintf("\nmodificado: %s  tamanho: %d KB", formataHora(info.ModTime()), info.Size()/1024)
				}
				r.Add(classe.Severidade(), "Arquivo bate com assinatura '"+t+"': "+d.Name(), detalhe)
				return nil
			}
			if ext == ".sys" {
				if h := sha256DoArquivo(caminho, 32*1024*1024); h != "" {
					if rotulo := c.A.HashConhecido(h); rotulo != "" {
						r.Add(Critico, "Driver com HASH conhecido no disco: "+d.Name(), caminho+"\nSHA256: "+h+"\nBate com: "+rotulo+"\nO hash nao muda quando o arquivo e renomeado")
						return nil
					}
				}
				if c.A.SysConhecidoDoSistema(d.Name()) || strings.Count(caminho, string(os.PathSeparator)) <= 1 {
					return nil
				}
				info, _ := d.Info()
				hora := time.Time{}
				if info != nil {
					hora = info.ModTime()
				}
				if c.A.DriverVulneravel(strings.ToLower(d.Name())) {
					r.Add(Alerta, "Driver da lista de vulneraveis (BYOVD) no disco: "+d.Name(), caminho+"\nmodificado: "+formataHora(hora)+"\nPode ser de utilitario de hardware. Conferir se o programa dono esta instalado")
					return nil
				}
				if driverDeAnticheatConhecido(d.Name()) {
					return nil
				}
				if quente && !strings.Contains(lower, `\sdk\`) && !strings.Contains(lower, `\drivers\`) && !strings.Contains(lower, `\driverstore\`) && !strings.Contains(lower, `\android\`) && !strings.Contains(lower, `\program files`) && !strings.Contains(lower, `\windows\`) {
					r.Add(Alerta, "Driver .sys solto em pasta de usuario: "+d.Name(), caminho+"\nmodificado: "+formataHora(hora))
				}
				return nil
			}
			if quente {
				if ext == ".exe" || ext == ".dll" {
					if h := sha256DoArquivo(caminho, 64*1024*1024); h != "" {
						if rotulo := c.A.HashConhecido(h); rotulo != "" {
							r.Add(Critico, "Arquivo com HASH de cheat conhecido: "+d.Name(), caminho+"\nSHA256: "+h+"\nBate com: "+rotulo+"\nO hash nao muda quando o arquivo e renomeado")
							return nil
						}
					}
					if pareceNomeAleatorio(d.Name()) {
						r.Add(Alerta, "Executavel com nome aleatorio: "+d.Name(), caminho)
						return nil
					}
					if info, err := d.Info(); err == nil && time.Since(info.ModTime()) < 7*24*time.Hour {
						recentes = append(recentes, arquivoAchado{Caminho: caminho, Hora: info.ModTime(), Tamanho: info.Size()})
					}
				} else if extensoesInocentes[ext] && !extensoesPE[ext] && !nomeDeBackupOuTemporario(d.Name(), caminho) && !arquivoDoProprioJogo(caminho) && !pacoteDeDriverOuInstalador(caminho) && ehExecutavelDisfarcado(caminho, d) {
					disfarcados = append(disfarcados, caminho)
				}
			}
			return nil
		})
	}

	for _, p := range pastasQuentes {
		visita(p, 8, true)
	}
	for _, p := range pastasNormais {
		visita(p, 7, false)
	}
	for _, u := range unidadesFixas() {
		visita(u, 3, true)
		visita(u, 40, false)
	}
	r.Linha("%d arquivos analisados em %s", total, time.Since(inicio).Round(time.Second))
	if estourouOTempo(inicio, limiteTempo) {
		r.Add(Alerta, "VARREDURA INCOMPLETA: parou por tempo", fmt.Sprintf("O limite de %s foi atingido e parte do disco NAO foi analisada. Rode de novo sem limite (a checagem completa nao tem limite por padrao) antes de concluir qualquer coisa sobre este PC", limiteTempo.Round(time.Second)))
	}

	for _, d := range disfarcados {
		r.Add(Critico, "Executavel DISFARCADO com outra extensao: "+filepath.Base(d), d+"\nO arquivo comeca com cabecalho MZ (programa Windows) mas nao tem extensao .exe/.dll")
	}
	sort.Slice(recentes, func(i, j int) bool { return recentes[i].Hora.After(recentes[j].Hora) })
	var linhas []string
	for _, a := range recentes {
		linhas = append(linhas, fmt.Sprintf("%s  %7d KB  %s", formataHora(a.Hora), a.Tamanho/1024, a.Caminho))
	}
	if len(linhas) > 0 {
		r.Add(Info, fmt.Sprintf("Executaveis novos/modificados nos ultimos 7 dias em pastas do usuario: %d", len(linhas)), strings.Join(limita(linhas, 200), "\n"))
	}
}

var extensoesInocentes = map[string]bool{
	"": true, ".txt": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true, ".mp3": true, ".mp4": true,
	".wav": true, ".dat": true, ".tmp": true, ".log": true, ".cfg": true, ".ini": true, ".json": true, ".xml": true, ".pdf": true,
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".zip": true, ".rar": true, ".7z": true, ".bak": true, ".old": true,
	".html": true, ".htm": true, ".css": true, ".js": true, ".lua": true, ".ttf": true, ".ico": true, ".cache": true, ".bin": true,
}

var extensoesDeImagemOuMidia = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".bmp": true, ".ico": true, ".svg": true,
	".mp4": true, ".mkv": true, ".webm": true, ".mp3": true, ".wav": true, ".ogg": true, ".ttf": true, ".otf": true,
	".woff": true, ".woff2": true, ".psd": true, ".ai": true, ".xcf": true, ".cur": true, ".ani": true,
}

var extensoesPE = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".scr": true, ".cpl": true, ".ocx": true, ".mui": true, ".pyd": true,
	".node": true, ".drv": true, ".efi": true, ".msstyles": true, ".ax": true, ".acm": true, ".ime": true, ".com": true,
	".winmd": true, ".rll": true, ".olb": true, ".tsp": true, ".fon": true, ".so": true, ".pf": true, ".lnk": true,
	".msi": true, ".msp": true, ".cab": true, ".xex": true, ".nlp": true, ".bpl": true, ".dpl": true, ".vxd": true,
}

func ehExecutavelDisfarcado(caminho string, d fs.DirEntry) bool {
	info, err := d.Info()
	if err != nil || info.Size() < 1024 || info.Size() > 200*1024*1024 {
		return false
	}
	f, err := os.Open(caminho)
	if err != nil {
		return false
	}
	defer f.Close()
	var cabecalho [2]byte
	if _, err := f.Read(cabecalho[:]); err != nil {
		return false
	}
	return cabecalho[0] == 'M' && cabecalho[1] == 'Z'
}

func checarFiveM(c *Contexto) {
	r := c.R
	r.Secao("FIVEM")
	encontrado := false
	for _, p := range c.Perfis {
		app := filepath.Join(p.Pasta, `AppData\Local\FiveM\FiveM.app`)
		if _, err := os.Stat(app); err != nil {
			continue
		}
		encontrado = true
		r.Linha("Instalacao de %s: %s", p.Usuario, app)

		for _, sub := range []string{"plugins", "mods"} {
			entradas, err := os.ReadDir(filepath.Join(app, sub))
			if err != nil {
				continue
			}
			for _, e := range entradas {
				caminho := filepath.Join(app, sub, e.Name())
				if e.IsDir() {
					continue
				}
				ext := strings.ToLower(filepath.Ext(e.Name()))
				if classe, t := c.A.Classificar(e.Name()); classe != SemMatch {
					r.Add(Critico, "Arquivo em FiveM.app\\"+sub+" bate com assinatura '"+t+"'", caminho)
					continue
				}
				nomeLower := strings.ToLower(e.Name())
				if ext == ".dll" && (nomeLower == "dxgi.dll" || nomeLower == "d3d11.dll" || nomeLower == "d3d12.dll" || strings.Contains(nomeLower, "reshade") || nomeLower == "opengl32.dll") {
					r.Add(Info, "Plugin grafico no FiveM (ReShade/ENB): "+e.Name(), caminho+"\nNome padrao de ReShade. Conferir se existe a pasta reshade-shaders ou ReShade.ini ao lado")
				} else if ext == ".asi" || ext == ".dll" {
					r.Add(Alerta, "Plugin carregado pelo FiveM: "+e.Name(), caminho+"\nQualquer .asi/.dll nessa pasta e injetado no jogo. Confirmar se e mod visual legitimo")
				} else if ext == ".rpf" {
					r.Add(Info, "Mod .rpf instalado no FiveM: "+e.Name(), caminho)
				}
			}
		}

		logs, _ := filepath.Glob(filepath.Join(app, "logs", "CitizenFX_log_*.log"))
		sort.Strings(logs)
		if len(logs) > 0 {
			ultimo := logs[len(logs)-1]
			conteudo, err := os.ReadFile(ultimo)
			if err == nil {
				var suspeitos []string
				for _, l := range strings.Split(string(conteudo), "\n") {
					if classe, t := c.A.Classificar(l); classe != SemMatch {
						suspeitos = append(suspeitos, "["+t+"] "+resume(l, 180))
					}
				}
				r.Linha("Ultimo log: %s (%d KB)", filepath.Base(ultimo), len(conteudo)/1024)
				if len(suspeitos) > 0 {
					r.Add(Critico, "Log do FiveM menciona assinatura de cheat", strings.Join(limita(suspeitos, 60), "\n"))
				}
			}
		}
	}
	if !encontrado {
		r.Add(Info, "FiveM.app nao encontrado em nenhum perfil", "Instalacao em local personalizado ou FiveM removido")
	}

	hosts := filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`)
	conteudo, err := os.ReadFile(hosts)
	if err == nil {
		var entradas []string
		for _, l := range strings.Split(string(conteudo), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			entradas = append(entradas, l)
			lower := strings.ToLower(l)
			if strings.Contains(lower, "cfx.re") || strings.Contains(lower, "fivem") || strings.Contains(lower, "citizenfx") || c.A.Dominio(lower) != "" {
				r.Add(Critico, "Arquivo hosts redireciona dominio do FiveM/cheat", l)
			}
		}
		if len(entradas) > 0 {
			r.Add(Info, fmt.Sprintf("Arquivo hosts tem %d entrada(s) personalizada(s)", len(entradas)), strings.Join(limita(entradas, 80), "\n"))
		}
	}
}

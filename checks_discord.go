package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	reAnexoDiscord   = regexp.MustCompile(`(?i)https?://(?:cdn|media)\.discordapp\.(?:com|net)/attachments/\d+/\d+/([^\s"'<>\x00]+)`)
	reConviteDiscord = regexp.MustCompile(`(?i)(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/([a-z0-9\-]{2,40})`)
)

var pastasDiscord = []string{"discord", "discordcanary", "discordptb", "discorddevelopment"}

var subpastasDiscord = []string{"Cache", "Code Cache", "Local Storage", "Session Storage", "IndexedDB", "blob_storage", "Service Worker", "sentry"}

type achadoDiscord struct {
	Termo      string
	Arquivo    string
	Contexto   string
	URL        string
	Modificado time.Time
}

type resultadoDiscord struct {
	RelatoriosColados int
	Arquivos          int
	Interrompido      bool
	Bytes             int64
	Mencoes           []achadoDiscord
	Anexos            map[string]string
	Convites          map[string]string
}

func analisarPastaDiscord(a *Assinaturas, raiz string, limite time.Duration, progresso informaProgresso) resultadoDiscord {
	return analisarPastaDiscordCancelavel(a, raiz, limite, progresso, nil)
}

func analisarPastaDiscordCancelavel(a *Assinaturas, raiz string, limite time.Duration, progresso informaProgresso, cancelar func() bool) resultadoDiscord {
	res := resultadoDiscord{Anexos: map[string]string{}, Convites: map[string]string{}}
	buscador := NovoBuscador(a.TermosParaConteudo())
	inicio := time.Now()
	vistos := map[string]bool{}
	ultimoAviso := time.Now()

	for _, sub := range subpastasDiscord {
		pasta := filepath.Join(raiz, sub)
		if !existe(pasta) {
			continue
		}
		filepath.WalkDir(pasta, func(caminho string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if estourouOTempo(inicio, limite) || (cancelar != nil && cancelar()) {
				res.Interrompido = true
				return filepath.SkipAll
			}
			if progresso != nil && time.Since(ultimoAviso) > 1500*time.Millisecond {
				ultimoAviso = time.Now()
				progresso(res.Arquivos, res.Bytes, sub)
			}
			info, err := d.Info()
			if err != nil || info.Size() == 0 || info.Size() > 64*1024*1024 {
				return nil
			}
			dados, err := os.ReadFile(caminho)
			if err != nil {
				return nil
			}
			res.Arquivos++
			res.Bytes += int64(len(dados))
			if contextoDeRelatorioDoScanner(string(dados)) {
				res.RelatoriosColados++
				return nil
			}

			for _, m := range reAnexoDiscord.FindAllSubmatch(dados, -1) {
				nome := string(m[1])
				if i := strings.IndexAny(nome, "?&"); i >= 0 {
					nome = nome[:i]
				}
				if ehDownloadExecutavel(nome) || a.PalavraWeb(nome) != "" {
					if _, ok := res.Anexos[nome]; !ok {
						res.Anexos[nome] = string(m[0])
					}
				}
			}
			for _, m := range reConviteDiscord.FindAllSubmatch(dados, -1) {
				slug := strings.ToLower(string(m[1]))
				if _, ok := res.Convites[slug]; !ok {
					res.Convites[slug] = string(m[0])
				}
			}

			porArquivo := 0
			buscador.Procurar(dados, func(o Ocorrencia) bool {
				chave := o.Termo + "|" + filepath.Base(caminho)
				if vistos[chave] {
					return true
				}
				url := ""
				if !o.UTF16 {
					url = urlEmVolta(dados, o.Inicio, o.Fim)
				}
				contexto := trechoEmVolta(dados, o.Inicio, o.Fim, o.UTF16)
				chaveContexto := o.Termo + "|" + contexto
				if vistos[chaveContexto] {
					return true
				}
				vistos[chave] = true
				vistos[chaveContexto] = true
				res.Mencoes = append(res.Mencoes, achadoDiscord{Termo: o.Termo, Arquivo: caminho, Contexto: contexto, URL: url, Modificado: info.ModTime()})
				porArquivo++
				return porArquivo < 8
			})
			return nil
		})
	}
	return res
}

func checarDiscord(c *Contexto) {
	r := c.R
	r.Secao("DISCORD (cache, armazenamento local e anexos)")
	encontrou := false
	for _, p := range c.Perfis {
		for _, nome := range pastasDiscord {
			raiz := filepath.Join(p.Pasta, "AppData", "Roaming", nome)
			if !existe(raiz) {
				continue
			}
			encontrou = true
			relatarDiscord(c, p.Usuario, nome, raiz)
		}
	}
	if !encontrou {
		r.Add(Info, "Discord nao encontrado em nenhum perfil", "Sem pasta AppData\\Roaming\\discord. Discord nao instalado ou dados apagados")
	}
}

func relatarDiscord(c *Contexto, usuario, nome, raiz string) {
	r := c.R
	inicio := time.Now()
	res := analisarPastaDiscordCancelavel(c.A, raiz, c.LimiteEtapa, func(arquivos int, bytes int64, atual string) {
		r.Progresso("%s de %s: %d arquivos (%d MB) em %s. Lendo: %s", nome, usuario, arquivos, bytes/1024/1024, time.Since(inicio).Round(time.Second), atual)
	}, c.DevePular)
	r.Linha("%s de %s: %d arquivos (%d MB) analisados em %s", nome, usuario, res.Arquivos, res.Bytes/1024/1024, raiz)

	if res.Interrompido {
		r.Add(Alerta, "LEITURA DO DISCORD INCOMPLETA: parou por tempo", "Parte do cache do Discord nao foi lida. Rode de novo sem limite")
	}
	if res.Arquivos < 20 {
		r.Add(Alerta, fmt.Sprintf("Cache do %s de %s quase vazio (%d arquivos)", nome, usuario, res.Arquivos), "Cache do Discord limpo recentemente. Quem limpa o cache do Discord antes de uma checagem esta escondendo algo")
	}

	porTermo := map[string][]achadoDiscord{}
	var termos []string
	relatoriosColados := res.RelatoriosColados
	for _, m := range res.Mencoes {
		if contextoDeRelatorioDoScanner(m.Contexto) {
			relatoriosColados++
			continue
		}
		if _, ok := porTermo[m.Termo]; !ok {
			termos = append(termos, m.Termo)
		}
		porTermo[m.Termo] = append(porTermo[m.Termo], m)
	}
	sort.Strings(termos)
	if relatoriosColados > 0 {
		r.Linha("%d arquivo(s) do cache eram relatorio deste scanner colado no Discord, ignorados", relatoriosColados)
	}
	for _, t := range termos {
		lista := porTermo[t]
		var linhas []string
		sev := Alerta
		for _, m := range lista {
			linha := formataHora(m.Modificado) + "  "
			if m.URL != "" {
				linha += m.URL
				if strings.Contains(strings.ToLower(m.URL), "attachments/") || c.A.Dominio(m.URL) != "" {
					sev = Critico
				}
			} else {
				linha += "..." + m.Contexto + "..."
			}
			linha += "\n    em: " + strings.TrimPrefix(m.Arquivo, raiz+string(os.PathSeparator))
			linhas = append(linhas, linha)
		}
		titulo := fmt.Sprintf("%s de %s menciona '%s' (%d ocorrencia(s))", nome, usuario, t, len(lista))
		r.Add(sev, titulo, strings.Join(limitaLinhas(linhas, 60), "\n"))
	}

	var anexos []string
	for nomeAnexo, url := range res.Anexos {
		if t := c.A.Marca(nomeAnexo); t != "" {
			r.Add(Critico, "Anexo do Discord bate com '"+t+"': "+nomeAnexo, url)
			continue
		}
		if classe, t := c.A.Classificar(nomeAnexo); classe != SemMatch && !c.A.TextoInocente(nomeAnexo) {
			r.Add(Alerta, "Anexo do Discord bate com '"+t+"': "+nomeAnexo, url)
			continue
		}
		if t := c.A.PalavraWeb(nomeAnexo); t != "" {
			r.Add(Alerta, "Anexo do Discord com o termo '"+t+"': "+nomeAnexo, url)
			continue
		}
		anexos = append(anexos, nomeAnexo+"  "+url)
	}
	sort.Strings(anexos)
	if len(anexos) > 0 {
		r.Add(Info, fmt.Sprintf("Anexos executaveis/compactados vistos no %s de %s: %d", nome, usuario, len(anexos)), strings.Join(limitaLinhas(anexos, 100), "\n"))
	}

	var convites []string
	for slug, url := range res.Convites {
		if t := c.A.Marca(slug); t != "" {
			r.Add(Critico, "Convite Discord de servidor de cheat ('"+t+"'): "+slug, url)
			continue
		}
		if classe, t := c.A.Classificar(slug); classe != SemMatch && !c.A.TextoInocente(slug) {
			r.Add(Critico, "Convite Discord de servidor de cheat ('"+t+"'): "+slug, url)
			continue
		}
		if t := c.A.PalavraWeb(slug); t != "" {
			r.Add(Critico, "Convite Discord com o termo '"+t+"': "+slug, url)
			continue
		}
		convites = append(convites, slug)
	}
	sort.Strings(convites)
	if len(convites) > 0 {
		r.Add(Info, fmt.Sprintf("Convites Discord vistos no cache de %s: %d", usuario, len(convites)), strings.Join(limitaLinhas(convites, 160), ", "))
	}

	if len(termos) == 0 && len(res.Anexos) == 0 {
		r.Ok("%s de %s: nenhuma mencao a cheat no cache", nome, usuario)
	}
}

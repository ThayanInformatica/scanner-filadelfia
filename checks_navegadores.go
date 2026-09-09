package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type registroNavegacao struct {
	Navegador string
	Tipo      string
	URL       string
	Titulo    string
	Hora      time.Time
}

type fonteHistorico struct {
	Navegador string
	Caminho   string
	Motor     string
}

const epocaChrome = 11644473600

func horaChrome(t int64) time.Time {
	if t <= 0 {
		return time.Time{}
	}
	return time.Unix(t/1000000-epocaChrome, (t%1000000)*1000).Local()
}

func horaFirefox(t int64) time.Time {
	if t <= 0 {
		return time.Time{}
	}
	return time.Unix(t/1000000, (t%1000000)*1000).Local()
}

func fontesDeHistorico(pastaPerfil string) []fonteHistorico {
	local := filepath.Join(pastaPerfil, "AppData", "Local")
	roaming := filepath.Join(pastaPerfil, "AppData", "Roaming")
	chromium := []struct{ nome, base string }{
		{"Chrome", filepath.Join(local, "Google", "Chrome", "User Data")},
		{"Edge", filepath.Join(local, "Microsoft", "Edge", "User Data")},
		{"Brave", filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data")},
		{"Vivaldi", filepath.Join(local, "Vivaldi", "User Data")},
		{"Chromium", filepath.Join(local, "Chromium", "User Data")},
		{"Opera", filepath.Join(roaming, "Opera Software", "Opera Stable")},
		{"Opera GX", filepath.Join(roaming, "Opera Software", "Opera GX Stable")},
	}
	var fontes []fonteHistorico
	for _, nav := range chromium {
		if h := filepath.Join(nav.base, "History"); existe(h) {
			fontes = append(fontes, fonteHistorico{nav.nome, h, "chromium"})
		}
		entradas, _ := os.ReadDir(nav.base)
		for _, e := range entradas {
			if !e.IsDir() {
				continue
			}
			nome := e.Name()
			if nome != "Default" && !strings.HasPrefix(nome, "Profile ") && !strings.HasPrefix(nome, "Guest") {
				continue
			}
			if h := filepath.Join(nav.base, nome, "History"); existe(h) {
				fontes = append(fontes, fonteHistorico{nav.nome + " (" + nome + ")", h, "chromium"})
			}
		}
	}
	perfisFirefox, _ := filepath.Glob(filepath.Join(roaming, "Mozilla", "Firefox", "Profiles", "*", "places.sqlite"))
	for _, p := range perfisFirefox {
		fontes = append(fontes, fonteHistorico{"Firefox (" + filepath.Base(filepath.Dir(p)) + ")", p, "firefox"})
	}
	return fontes
}

func existe(caminho string) bool {
	_, err := os.Stat(caminho)
	return err == nil
}

func copiaParaTemp(origem string) (string, error) {
	src, err := os.Open(origem)
	if err != nil {
		return "", err
	}
	defer src.Close()
	dst, err := os.CreateTemp("", "scanner-hist-*.db")
	if err != nil {
		return "", err
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		os.Remove(dst.Name())
		return "", err
	}
	return dst.Name(), nil
}

func abrirSQLiteSomenteLeitura(caminho string) (*sql.DB, string, error) {
	copia, err := copiaParaTemp(caminho)
	if err != nil {
		return nil, "", err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(copia)+"?mode=ro&immutable=1")
	if err != nil {
		os.Remove(copia)
		return nil, "", err
	}
	return db, copia, nil
}

func lerHistoricoChromium(navegador, caminho string) ([]registroNavegacao, error) {
	db, copia, err := abrirSQLiteSomenteLeitura(caminho)
	if err != nil {
		return nil, err
	}
	defer os.Remove(copia)
	defer db.Close()

	var lista []registroNavegacao
	linhas, err := db.Query(`SELECT url, IFNULL(title,''), last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 30000`)
	if err != nil {
		return nil, err
	}
	for linhas.Next() {
		var url, titulo string
		var hora int64
		if linhas.Scan(&url, &titulo, &hora) == nil {
			lista = append(lista, registroNavegacao{navegador, "visita", url, titulo, horaChrome(hora)})
		}
	}
	linhas.Close()

	if downloads, err := db.Query(`SELECT IFNULL(target_path,''), IFNULL(tab_url,''), start_time FROM downloads ORDER BY start_time DESC LIMIT 3000`); err == nil {
		for downloads.Next() {
			var alvo, url string
			var hora int64
			if downloads.Scan(&alvo, &url, &hora) == nil {
				lista = append(lista, registroNavegacao{navegador, "download", url, alvo, horaChrome(hora)})
			}
		}
		downloads.Close()
	}

	if buscas, err := db.Query(`SELECT k.term, IFNULL(u.last_visit_time,0) FROM keyword_search_terms k LEFT JOIN urls u ON u.id = k.url_id`); err == nil {
		for buscas.Next() {
			var termo string
			var hora int64
			if buscas.Scan(&termo, &hora) == nil {
				lista = append(lista, registroNavegacao{navegador, "busca", "", termo, horaChrome(hora)})
			}
		}
		buscas.Close()
	}
	return lista, nil
}

func lerHistoricoFirefox(navegador, caminho string) ([]registroNavegacao, error) {
	db, copia, err := abrirSQLiteSomenteLeitura(caminho)
	if err != nil {
		return nil, err
	}
	defer os.Remove(copia)
	defer db.Close()

	var lista []registroNavegacao
	linhas, err := db.Query(`SELECT url, IFNULL(title,''), IFNULL(last_visit_date,0) FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 30000`)
	if err != nil {
		return nil, err
	}
	for linhas.Next() {
		var url, titulo string
		var hora int64
		if linhas.Scan(&url, &titulo, &hora) == nil {
			lista = append(lista, registroNavegacao{navegador, "visita", url, titulo, horaFirefox(hora)})
		}
	}
	linhas.Close()

	if downloads, err := db.Query(`SELECT a.content, IFNULL(p.url,''), IFNULL(a.dateAdded,0) FROM moz_annos a JOIN moz_anno_attributes t ON t.id = a.anno_attribute_id LEFT JOIN moz_places p ON p.id = a.place_id WHERE t.name = 'downloads/destinationFileURI'`); err == nil {
		for downloads.Next() {
			var alvo, url string
			var hora int64
			if downloads.Scan(&alvo, &url, &hora) == nil {
				lista = append(lista, registroNavegacao{navegador, "download", url, strings.TrimPrefix(alvo, "file:///"), horaFirefox(hora)})
			}
		}
		downloads.Close()
	}
	return lista, nil
}

type grupoNavegacao struct {
	Severidade Severidade
	Titulo     string
	Linhas     []string
	Total      int
}

func avaliarNavegacao(c *Contexto, registros []registroNavegacao) []grupoNavegacao {
	grupos := map[string]*grupoNavegacao{}
	ordem := []string{}
	adiciona := func(chave string, sev Severidade, titulo string, linha string) {
		g, ok := grupos[chave]
		if !ok {
			g = &grupoNavegacao{Severidade: sev, Titulo: titulo}
			grupos[chave] = g
			ordem = append(ordem, chave)
		}
		g.Total++
		if len(g.Linhas) < 15 {
			g.Linhas = append(g.Linhas, linha)
		}
	}

	vistos := map[string]bool{}
	var downloadsExe []string
	for _, r := range registros {
		texto := r.URL + " " + r.Titulo
		chaveVista := r.Tipo + "|" + strings.ToLower(texto)
		if vistos[chaveVista] {
			continue
		}
		vistos[chaveVista] = true
		linha := formataHora(r.Hora) + "  " + r.URL
		if r.Titulo != "" {
			linha += "  [" + resumeTexto(r.Titulo, 80) + "]"
		}

		temFivem := strings.Contains(strings.ToLower(texto), "fivem") || strings.Contains(strings.ToLower(texto), "cfx.re") || strings.Contains(strings.ToLower(texto), "gta")
		switch r.Tipo {
		case "busca":
			linha = formataHora(r.Hora) + "  pesquisou: " + r.Titulo
			if t := c.A.Marca(r.Titulo); t != "" {
				adiciona(r.Navegador+"|busca|"+t, Critico, r.Navegador+": pesquisas por '"+t+"'", linha)
			} else if t := c.A.Dominio(r.Titulo); t != "" {
				adiciona(r.Navegador+"|busca|"+t, Critico, r.Navegador+": pesquisas por '"+t+"'", linha)
			} else if classe, t := c.A.Classificar(r.Titulo); classe != SemMatch && !c.A.TextoInocente(r.Titulo) {
				sev := Alerta
				if temFivem {
					sev = Critico
				}
				adiciona(r.Navegador+"|busca|"+t, sev, r.Navegador+": pesquisas por '"+t+"'", linha)
			} else if t := c.A.PalavraWeb(r.Titulo); t != "" {
				sev := Alerta
				if temFivem {
					sev = Critico
				}
				adiciona(r.Navegador+"|buscaweb|"+t, sev, r.Navegador+": pesquisas com o termo '"+t+"'", linha)
			}
		case "download":
			linha = formataHora(r.Hora) + "  " + r.Titulo + "  <- " + r.URL
			if t := c.A.Dominio(r.URL); t != "" {
				adiciona(r.Navegador+"|down|"+t, Critico, r.Navegador+": download de site de cheat ('"+t+"')", linha)
			} else if t := c.A.Marca(texto); t != "" {
				adiciona(r.Navegador+"|down|"+t, Critico, r.Navegador+": download bate com '"+t+"'", linha)
			} else if classe, t := c.A.Classificar(texto); classe != SemMatch && !c.A.TextoInocente(texto) {
				sev := classe.Severidade()
				if sev == Critico && !temFivem {
					sev = Alerta
				}
				adiciona(r.Navegador+"|down|"+t, sev, r.Navegador+": download bate com '"+t+"'", linha)
			} else if t := c.A.PalavraWeb(texto); t != "" {
				adiciona(r.Navegador+"|downweb|"+t, Alerta, r.Navegador+": download com o termo '"+t+"'", linha)
			} else if site := ehSiteDeCompartilhamento(r.URL); site != "" && arquivoDoUniversoDoJogo(r.Titulo) != "" {
				adiciona(r.Navegador+"|compart|"+site, Critico, r.Navegador+": arquivo do jogo baixado de site de compartilhamento ("+site+")", linha+"\nArquivo do FiveM/GTA nao vem de MediaFire, Google Drive ou Discord: vem do site oficial. Pacote do jogo distribuido assim costuma ser versao modificada para burlar anticheat")
			} else if site := ehSiteDeCompartilhamento(r.URL); site != "" && ehDownloadExecutavel(r.Titulo) {
				adiciona(r.Navegador+"|compartexe|"+site, Alerta, r.Navegador+": programa baixado de site de compartilhamento ("+site+")", linha+"\nExecutavel ou pacote vindo de link avulso, sem site oficial. Conferir o que e")
			} else if ehDownloadExecutavel(r.Titulo) && time.Since(r.Hora) < 30*24*time.Hour {
				downloadsExe = append(downloadsExe, linha)
			}
		default:
			if t := c.A.Dominio(r.URL); t != "" {
				adiciona(r.Navegador+"|site|"+t, Critico, r.Navegador+": acessos a site de cheat ('"+t+"')", linha)
			} else if t := c.A.Marca(texto); t != "" {
				adiciona(r.Navegador+"|marca|"+t, Critico, r.Navegador+": paginas sobre '"+t+"'", linha)
			} else if ehConviteDiscord(r.URL) {
				if t := c.A.PalavraWeb(r.URL); t != "" {
					adiciona(r.Navegador+"|convite|"+t, Critico, r.Navegador+": convite Discord com '"+t+"'", linha)
				} else if classe, t := c.A.Classificar(r.URL); classe != SemMatch {
					adiciona(r.Navegador+"|convite|"+t, Critico, r.Navegador+": convite Discord com '"+t+"'", linha)
				}
			} else if classe, t := c.A.Classificar(texto); classe != SemMatch && !c.A.TextoInocente(texto) {
				sev := Alerta
				if temFivem && classe == ClasseCheat {
					sev = Critico
				}
				adiciona(r.Navegador+"|url|"+t, sev, r.Navegador+": paginas que batem com '"+t+"'", linha)
			} else if t := c.A.PalavraWeb(texto); t != "" && (temFivem || !siteDeConteudo(r.URL)) {
				sev := Alerta
				if temFivem {
					sev = Critico
				}
				adiciona(r.Navegador+"|web|"+t, sev, r.Navegador+": paginas com o termo '"+t+"'", linha)
			}
		}
	}

	var saida []grupoNavegacao
	for _, k := range ordem {
		saida = append(saida, *grupos[k])
	}
	sort.SliceStable(saida, func(i, j int) bool { return saida[i].Severidade > saida[j].Severidade })
	if len(downloadsExe) > 0 {
		saida = append(saida, grupoNavegacao{Severidade: Info, Titulo: fmt.Sprintf("Downloads de executaveis/compactados nos ultimos 30 dias: %d", len(downloadsExe)), Linhas: limitaLinhas(downloadsExe, 100), Total: len(downloadsExe)})
	}
	return saida
}

func siteDeConteudo(url string) bool {
	u := strings.ToLower(url)
	for _, h := range []string{"youtube.com/", "youtu.be/", "reddit.com/", "twitter.com/", "x.com/", "tiktok.com/", "instagram.com/", "facebook.com/", "twitch.tv/", "kick.com/", "steamcommunity.com/", "store.steampowered.com/", "spotify.com/", "netflix.com/", "globo.com/", "uol.com.br/", "g1.globo", "wikipedia.org/", "medium.com/", "news."} {
		if strings.Contains(u, h) {
			return true
		}
	}
	return false
}

func ehConviteDiscord(url string) bool {
	u := strings.ToLower(url)
	return strings.Contains(u, "discord.gg/") || strings.Contains(u, "discord.com/invite/") || strings.Contains(u, "discordapp.com/invite/")
}

func ehDownloadExecutavel(caminho string) bool {
	ext := strings.ToLower(filepath.Ext(caminho))
	switch ext {
	case ".exe", ".dll", ".sys", ".rar", ".zip", ".7z", ".bat", ".ps1", ".msi", ".asi":
		return true
	}
	return false
}

func resumeTexto(texto string, max int) string {
	texto = strings.Join(strings.Fields(texto), " ")
	if len(texto) > max {
		return texto[:max] + "..."
	}
	return texto
}

func limitaLinhas(linhas []string, max int) []string {
	if len(linhas) <= max {
		return linhas
	}
	return append(append([]string{}, linhas[:max]...), fmt.Sprintf("... e mais %d", len(linhas)-max))
}

func checarNavegadores(c *Contexto) {
	r := c.R
	r.Secao("HISTORICO DOS NAVEGADORES")
	encontrou := false
	for _, p := range c.Perfis {
		for _, fonte := range fontesDeHistorico(p.Pasta) {
			encontrou = true
			var registros []registroNavegacao
			var err error
			if fonte.Motor == "firefox" {
				registros, err = lerHistoricoFirefox(fonte.Navegador, fonte.Caminho)
			} else {
				registros, err = lerHistoricoChromium(fonte.Navegador, fonte.Caminho)
			}
			if err != nil {
				r.Erro("%s de %s: %v", fonte.Navegador, p.Usuario, err)
				continue
			}
			relatarNavegacao(c, p.Usuario, fonte.Navegador, registros)
			c.R.Progresso("Varredura profunda em %s de %s (cookies, contas salvas, favoritos, abas)", fonte.Navegador, p.Usuario)
			varreduraProfundaDoNavegador(c, p.Usuario, fonte.Navegador, fonte.Caminho, fonte.Motor)
		}
	}
	if !encontrou {
		r.Add(Alerta, "Nenhum historico de navegador encontrado", "Sem Chrome, Edge, Brave, Opera, Vivaldi ou Firefox com historico. Navegador removido, perfil apagado ou uso so em modo anonimo")
	}
}

func relatarNavegacao(c *Contexto, usuario, navegador string, registros []registroNavegacao) {
	r := c.R
	visitas, downloads, buscas := 0, 0, 0
	var maisAntiga, maisNova time.Time
	for _, reg := range registros {
		switch reg.Tipo {
		case "visita":
			visitas++
			if !reg.Hora.IsZero() && (maisAntiga.IsZero() || reg.Hora.Before(maisAntiga)) {
				maisAntiga = reg.Hora
			}
			if reg.Hora.After(maisNova) {
				maisNova = reg.Hora
			}
		case "download":
			downloads++
		case "busca":
			buscas++
		}
	}
	r.Linha("%s de %s: %d paginas, %d downloads, %d pesquisas. Mais antiga: %s  Mais recente: %s", navegador, usuario, visitas, downloads, buscas, formataHora(maisAntiga), formataHora(maisNova))

	if visitas == 0 {
		r.Add(Alerta, navegador+" de "+usuario+" com historico VAZIO", "Historico limpo ou navegador nunca usado")
	} else if visitas < 30 && !c.Instalacao.IsZero() && time.Since(c.Instalacao) > 7*24*time.Hour {
		r.Add(Alerta, fmt.Sprintf("%s de %s com historico quase vazio (%d paginas)", navegador, usuario, visitas), "Historico limpo recentemente ou navegador secundario")
	} else if !maisAntiga.IsZero() && !c.Instalacao.IsZero() && time.Since(c.Instalacao) > 7*24*time.Hour && time.Since(maisAntiga) < 48*time.Hour {
		r.Add(Alerta, fmt.Sprintf("%s de %s so tem historico das ultimas %s", navegador, usuario, time.Since(maisAntiga).Round(time.Hour)), "Historico limpo ha pouco tempo")
	}

	grupos := avaliarNavegacao(c, registros)
	if len(grupos) == 0 {
		r.Ok("%s de %s: nada de cheat no historico", navegador, usuario)
	}
	for _, g := range grupos {
		titulo := g.Titulo
		if g.Total > 1 && g.Severidade != Info {
			titulo = fmt.Sprintf("%s (%d)", g.Titulo, g.Total)
		}
		r.Add(g.Severidade, titulo, strings.Join(g.Linhas, "\n"))
	}
}

type consultaExtra struct {
	Arquivo string
	SQL     string
	Tipo    string
	Rotulo  string
}

var consultasChromium = []consultaExtra{
	{"Network/Cookies", `SELECT host_key, name, CAST(creation_utc AS TEXT) FROM cookies LIMIT 20000`, "cookie", "cookie salvo"},
	{"Cookies", `SELECT host_key, name, CAST(creation_utc AS TEXT) FROM cookies LIMIT 20000`, "cookie", "cookie salvo"},
	{"Login Data", `SELECT origin_url, IFNULL(username_value,''), CAST(date_created AS TEXT) FROM logins LIMIT 5000`, "login", "conta salva no navegador"},
	{"Top Sites", `SELECT url, IFNULL(title,''), '0' FROM top_sites LIMIT 5000`, "topsite", "site mais visitado"},
	{"Shortcuts", `SELECT IFNULL(url,''), text, CAST(last_access_time AS TEXT) FROM omni_box_shortcuts LIMIT 5000`, "omnibox", "digitado na barra de endereco"},
	{"Favicons", `SELECT page_url, '', '0' FROM icon_mapping LIMIT 20000`, "favicon", "icone de site guardado"},
	{"Web Data", `SELECT origin_url, IFNULL(name,''), '0' FROM autofill_profiles LIMIT 2000`, "autofill", "formulario preenchido"},
}

var consultasFirefox = []consultaExtra{
	{"cookies.sqlite", `SELECT host, name, CAST(creationTime AS TEXT) FROM moz_cookies LIMIT 20000`, "cookie", "cookie salvo"},
	{"favicons.sqlite", `SELECT page_url, '', '0' FROM moz_pages_w_icons LIMIT 20000`, "favicon", "icone de site guardado"},
}

func lerConsultaExtra(navegador, base string, q consultaExtra) []registroNavegacao {
	caminho := filepath.Join(base, filepath.FromSlash(q.Arquivo))
	if !existe(caminho) {
		return nil
	}
	db, copia, err := abrirSQLiteSomenteLeitura(caminho)
	if err != nil {
		return nil
	}
	defer os.Remove(copia)
	defer db.Close()
	linhas, err := db.Query(q.SQL)
	if err != nil {
		return nil
	}
	defer linhas.Close()
	var lista []registroNavegacao
	for linhas.Next() {
		var a, b, c string
		if linhas.Scan(&a, &b, &c) != nil {
			continue
		}
		hora := time.Time{}
		if n, err := strconv.ParseInt(c, 10, 64); err == nil && n > 0 {
			if q.Tipo == "cookie" && strings.HasSuffix(q.Arquivo, "cookies.sqlite") {
				hora = horaFirefox(n)
			} else {
				hora = horaChrome(n)
			}
		}
		lista = append(lista, registroNavegacao{navegador, q.Tipo, a, b, hora})
	}
	return lista
}

func lerFavoritosChromium(navegador, base string) []registroNavegacao {
	dados, err := os.ReadFile(filepath.Join(base, "Bookmarks"))
	if err != nil {
		return nil
	}
	var raiz map[string]any
	if json.Unmarshal(dados, &raiz) != nil {
		return nil
	}
	var lista []registroNavegacao
	var caminha func(n any)
	caminha = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			if url, ok := v["url"].(string); ok {
				nome, _ := v["name"].(string)
				lista = append(lista, registroNavegacao{navegador, "favorito", url, nome, time.Time{}})
			}
			for _, filho := range v {
				caminha(filho)
			}
		case []any:
			for _, filho := range v {
				caminha(filho)
			}
		}
	}
	caminha(raiz)
	return lista
}

func lerExtensoesChromium(navegador, base string) []registroNavegacao {
	var lista []registroNavegacao
	manifestos, _ := filepath.Glob(filepath.Join(base, "Extensions", "*", "*", "manifest.json"))
	for _, m := range manifestos {
		dados, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var manifesto map[string]any
		if json.Unmarshal(dados, &manifesto) != nil {
			continue
		}
		nome, _ := manifesto["name"].(string)
		if nome == "" || strings.HasPrefix(nome, "__MSG_") {
			nome = filepath.Base(filepath.Dir(filepath.Dir(m)))
		}
		descricao, _ := manifesto["description"].(string)
		lista = append(lista, registroNavegacao{navegador, "extensao", m, nome + " " + descricao, time.Time{}})
	}
	return lista
}

func lerSessoesChromium(navegador, base string, a *Assinaturas) []registroNavegacao {
	var lista []registroNavegacao
	padroes := []string{"Current Session", "Current Tabs", "Last Session", "Last Tabs",
		filepath.Join("Sessions", "Session_*"), filepath.Join("Sessions", "Tabs_*")}
	buscador := NovoBuscador(append(append([]string{}, a.Marcas...), a.Dominios...))
	for _, p := range padroes {
		arquivos, _ := filepath.Glob(filepath.Join(base, p))
		for _, arq := range arquivos {
			dados, err := os.ReadFile(arq)
			if err != nil || len(dados) > 40*1024*1024 {
				continue
			}
			info, _ := os.Stat(arq)
			hora := time.Time{}
			if info != nil {
				hora = info.ModTime()
			}
			vistos := map[string]bool{}
			buscador.Procurar(dados, func(o Ocorrencia) bool {
				url := ""
				if !o.UTF16 {
					url = urlEmVolta(dados, o.Inicio, o.Fim)
				}
				if url == "" {
					url = trechoEmVolta(dados, o.Inicio, o.Fim, o.UTF16)
				}
				if vistos[url] {
					return true
				}
				vistos[url] = true
				lista = append(lista, registroNavegacao{navegador, "aba", url, "aba aberta ou restaurada (" + filepath.Base(arq) + ")", hora})
				return len(vistos) < 20
			})
		}
	}
	return lista
}

func avaliarExtras(c *Contexto, navegador, usuario string, registros []registroNavegacao) {
	r := c.R
	grupos := map[string]*grupoNavegacao{}
	var ordem []string
	adiciona := func(chave string, sev Severidade, titulo, linha string) {
		g, ok := grupos[chave]
		if !ok {
			g = &grupoNavegacao{Severidade: sev, Titulo: titulo}
			grupos[chave] = g
			ordem = append(ordem, chave)
		}
		g.Total++
		if len(g.Linhas) < 12 {
			g.Linhas = append(g.Linhas, linha)
		}
	}
	rotulos := map[string]string{
		"cookie": "cookie de", "login": "CONTA SALVA em", "topsite": "site mais visitado", "omnibox": "endereco digitado",
		"favicon": "icone guardado de", "favorito": "favorito", "aba": "aba aberta", "extensao": "extensao", "autofill": "formulario de",
	}
	vistos := map[string]bool{}
	for _, reg := range registros {
		texto := reg.URL + " " + reg.Titulo
		chave := reg.Tipo + "|" + strings.ToLower(texto)
		if vistos[chave] {
			continue
		}
		vistos[chave] = true
		rotulo := rotulos[reg.Tipo]
		linha := formataHora(reg.Hora) + "  " + strings.TrimSpace(reg.URL+"  "+reg.Titulo)
		sev := Critico
		termo := c.A.Dominio(texto)
		if termo == "" {
			termo = c.A.Marca(texto)
		}
		if termo == "" {
			if classe, t := c.A.Classificar(texto); classe != SemMatch && !c.A.TextoInocente(texto) {
				termo, sev = t, Alerta
				if reg.Tipo == "login" || reg.Tipo == "cookie" {
					sev = Critico
				}
			}
		}
		if termo == "" {
			continue
		}
		titulo := fmt.Sprintf("%s: %s '%s'", navegador, rotulo, termo)
		if reg.Tipo == "login" {
			titulo = fmt.Sprintf("%s: CONTA SALVA em site de cheat ('%s')", navegador, termo)
		}
		adiciona(reg.Tipo+"|"+termo, sev, titulo, linha)
	}
	for _, k := range ordem {
		g := grupos[k]
		titulo := g.Titulo
		if g.Total > 1 {
			titulo = fmt.Sprintf("%s (%d)", g.Titulo, g.Total)
		}
		detalhe := strings.Join(g.Linhas, "\n")
		if strings.HasPrefix(k, "cookie|") {
			detalhe += "\nCookie sobrevive a limpeza de historico. Se o cookie do site de cheat esta aqui, o site foi acessado e logado nesse navegador"
		}
		if strings.HasPrefix(k, "login|") {
			detalhe += "\nConta salva significa que o jogador criou login no site, nao apenas visitou"
		}
		r.Add(g.Severidade, titulo, detalhe)
	}
}

func varreduraProfundaDoNavegador(c *Contexto, usuario, navegador, caminhoHistorico, motor string) {
	base := filepath.Dir(caminhoHistorico)
	var extras []registroNavegacao
	if motor == "firefox" {
		for _, q := range consultasFirefox {
			extras = append(extras, lerConsultaExtra(navegador, base, q)...)
		}
		if dados, err := os.ReadFile(filepath.Join(base, "logins.json")); err == nil {
			var doc map[string]any
			if json.Unmarshal(dados, &doc) == nil {
				for _, item := range objetosDeQualquer(doc["logins"]) {
					url, _ := item["hostname"].(string)
					extras = append(extras, registroNavegacao{navegador, "login", url, "", time.Time{}})
				}
			}
		}
	} else {
		for _, q := range consultasChromium {
			extras = append(extras, lerConsultaExtra(navegador, base, q)...)
		}
		extras = append(extras, lerFavoritosChromium(navegador, base)...)
		extras = append(extras, lerExtensoesChromium(navegador, base)...)
		extras = append(extras, lerSessoesChromium(navegador, base, c.A)...)
	}
	if len(extras) == 0 {
		return
	}
	porTipo := map[string]int{}
	for _, e := range extras {
		porTipo[e.Tipo]++
	}
	var resumo []string
	for _, t := range []string{"cookie", "login", "favorito", "omnibox", "topsite", "favicon", "aba", "extensao", "autofill"} {
		if porTipo[t] > 0 {
			resumo = append(resumo, fmt.Sprintf("%s=%d", t, porTipo[t]))
		}
	}
	c.R.Linha("%s de %s (varredura profunda): %s", navegador, usuario, strings.Join(resumo, "  "))
	avaliarExtras(c, navegador, usuario, extras)
}

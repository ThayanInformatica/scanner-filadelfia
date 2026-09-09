package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func assinaturasDeTeste(t *testing.T) *Assinaturas {
	t.Helper()
	if _, err := os.Stat("assinaturas.json"); err != nil {
		t.Skip("assinaturas.json nao esta neste clone: a lista real fica no servidor da equipe, nao no repositorio")
	}
	a, _, err := CarregarAssinaturas("assinaturas.json")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func relatorioDeTeste() *Relatorio {
	r := NovoRelatorio("teste", false)
	r.silencioso = true
	return r
}

func temAchado(r *Relatorio, sev Severidade, trecho string) bool {
	for _, a := range r.Achados {
		if a.Severidade == sev && strings.Contains(strings.ToLower(a.Titulo+" "+a.Detalhe), strings.ToLower(trecho)) {
			return true
		}
	}
	return false
}

func TestBuscadorEncontraAsciiEUtf16ComBorda(t *testing.T) {
	b := NovoBuscador([]string{"eulen", "skript.gg", "hx"})
	dados := append([]byte("xx EULEN yy hxz hx ok \x00\x00"), utf16LE("visite skript.gg agora")...)
	var vistos []string
	b.Procurar(dados, func(o Ocorrencia) bool {
		vistos = append(vistos, o.Termo)
		return true
	})
	junto := strings.Join(vistos, ",")
	if !strings.Contains(junto, "eulen") || !strings.Contains(junto, "skript.gg") {
		t.Fatalf("faltou termo: %v", vistos)
	}
	if strings.Count(junto, "hx") != 1 {
		t.Fatalf("hx devia casar so como palavra inteira: %v", vistos)
	}
}

func TestBuscadorExtraiURL(t *testing.T) {
	dados := []byte(`{"url":"https://cdn.discordapp.com/attachments/1/2/eulen_loader.exe","x":1}`)
	b := NovoBuscador([]string{"eulen"})
	var url string
	b.Procurar(dados, func(o Ocorrencia) bool {
		url = urlEmVolta(dados, o.Inicio, o.Fim)
		return false
	})
	if url != "https://cdn.discordapp.com/attachments/1/2/eulen_loader.exe" {
		t.Fatalf("url errada: %q", url)
	}
}

func criaHistoricoChrome(t *testing.T, dir string) string {
	t.Helper()
	caminho := filepath.Join(dir, "History")
	db, err := sql.Open("sqlite", caminho)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	agora := (time.Now().Unix() + epocaChrome) * 1000000
	cmds := []string{
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER)`,
		`CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, start_time INTEGER, total_bytes INTEGER)`,
		`CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, lower_term TEXT, term TEXT)`,
		`INSERT INTO urls VALUES(1,'https://www.google.com/search?q=fivem+cheat+gratis','fivem cheat gratis - Pesquisa Google',1,1,` + itoa(agora) + `,0)`,
		`INSERT INTO urls VALUES(2,'https://eulen.cc/login','Eulen - Login',3,0,` + itoa(agora-1000000) + `,0)`,
		`INSERT INTO urls VALUES(3,'https://discord.gg/fivemcheat','Discord',1,0,` + itoa(agora-2000000) + `,0)`,
		`INSERT INTO urls VALUES(4,'https://www.youtube.com/watch?v=abc','Video de gato',1,0,` + itoa(agora-3000000) + `,0)`,
		`INSERT INTO urls VALUES(5,'https://news.ycombinator.com/','Hacker News',1,0,` + itoa(agora-4000000) + `,0)`,
		`INSERT INTO downloads VALUES(1,'C:\Users\jogador\Downloads\loader_v2.rar','https://eulen.cc/download',` + itoa(agora) + `,1234)`,
		`INSERT INTO downloads VALUES(2,'C:\Users\jogador\Downloads\GeForce_setup.exe','https://www.nvidia.com/',` + itoa(agora) + `,999)`,
		`INSERT INTO keyword_search_terms VALUES(1,1,'fivem cheat gratis','fivem cheat gratis')`,
	}
	for _, c := range cmds {
		if _, err := db.Exec(c); err != nil {
			t.Fatalf("%s: %v", c, err)
		}
	}
	return caminho
}

func itoa(v int64) string {
	return strings.TrimSpace(strings.Replace(strings.Replace(string(rune(0))+"", string(rune(0)), "", 1), " ", "", -1)) + formataInt(v)
}

func formataInt(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestHistoricoChromeDetectaSiteBuscaEDownload(t *testing.T) {
	dir := t.TempDir()
	caminho := criaHistoricoChrome(t, dir)
	registros, err := lerHistoricoChromium("Chrome", caminho)
	if err != nil {
		t.Fatal(err)
	}
	if len(registros) != 8 {
		t.Fatalf("esperava 8 registros, veio %d", len(registros))
	}
	r := relatorioDeTeste()
	c := &Contexto{R: r, A: assinaturasDeTeste(t), Instalacao: time.Now().Add(-30 * 24 * time.Hour)}
	relatarNavegacao(c, "jogador", "Chrome", registros)

	if !temAchado(r, Critico, "acessos a site de cheat ('eulen.cc')") {
		t.Errorf("nao detectou acesso ao eulen.cc: %+v", r.Achados)
	}
	if !temAchado(r, Critico, "pesquisas por") && !temAchado(r, Critico, "pesquisas com o termo") {
		t.Errorf("nao detectou a pesquisa por cheat: %+v", r.Achados)
	}
	if !temAchado(r, Critico, "download de site de cheat") {
		t.Errorf("nao detectou download do eulen: %+v", r.Achados)
	}
	if !temAchado(r, Critico, "discord.gg/fivemcheat") {
		t.Errorf("nao detectou convite discord.gg/fivemcheat: %+v", r.Achados)
	}
	if temAchado(r, Alerta, "ycombinator") || temAchado(r, Critico, "ycombinator") {
		t.Errorf("Hacker News nao devia ser flagrado: %+v", r.Achados)
	}
	if !temAchado(r, Info, "GeForce_setup.exe") {
		t.Errorf("download legitimo devia aparecer so como info: %+v", r.Achados)
	}
}

func TestFontesDeHistoricoEncontraPerfisChromium(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "AppData", "Local", "Google", "Chrome", "User Data")
	os.MkdirAll(filepath.Join(base, "Default"), 0o755)
	os.MkdirAll(filepath.Join(base, "Profile 2"), 0o755)
	os.MkdirAll(filepath.Join(base, "System Profile"), 0o755)
	for _, p := range []string{"Default", "Profile 2", "System Profile"} {
		os.WriteFile(filepath.Join(base, p, "History"), []byte("x"), 0o644)
	}
	fontes := fontesDeHistorico(dir)
	if len(fontes) != 2 {
		t.Fatalf("esperava 2 perfis, veio %d: %+v", len(fontes), fontes)
	}
}

func TestDiscordDetectaMencaoAnexoEConvite(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "Cache", "Cache_Data")
	os.MkdirAll(cache, 0o755)
	local := filepath.Join(dir, "Local Storage", "leveldb")
	os.MkdirAll(local, 0o755)
	os.WriteFile(filepath.Join(cache, "f_000001"), []byte(`GET https://cdn.discordapp.com/attachments/111/222/susano_loader.exe?ex=1 HTTP/1.1 ... https://discord.gg/fivemcheat ... https://discord.gg/meuservidorrp`), 0o644)
	os.WriteFile(filepath.Join(local, "000003.ldb"), append([]byte("ruido"), utf16LE("alguem tem a key do skript.gg pra me passar")...), 0o644)
	os.WriteFile(filepath.Join(cache, "f_000002"), []byte("conteudo normal de rp, nada de errado aqui"), 0o644)

	r := relatorioDeTeste()
	c := &Contexto{R: r, A: assinaturasDeTeste(t)}
	relatarDiscord(c, "jogador", "discord", dir)

	if !temAchado(r, Critico, "susano_loader.exe") {
		t.Errorf("nao detectou anexo de cheat: %+v", r.Achados)
	}
	if !temAchado(r, Critico, "fivemcheat") {
		t.Errorf("nao detectou convite de cheat: %+v", r.Achados)
	}
	if !temAchado(r, Alerta, "skript.gg") && !temAchado(r, Critico, "skript.gg") {
		t.Errorf("nao detectou mencao utf16 ao skript.gg: %+v", r.Achados)
	}
	if !temAchado(r, Info, "meuservidorrp") {
		t.Errorf("convite normal devia aparecer como info: %+v", r.Achados)
	}
}

func TestConteudoDetectaStringEmExeEScript(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "Downloads"), 0o755)
	os.MkdirAll(filepath.Join(dir, "Documents"), 0o755)
	exe := append([]byte("MZ\x90\x00binario\x00\x00"), utf16LE("RedEngine Loader v3")...)
	os.WriteFile(filepath.Join(dir, "Downloads", "update.exe"), exe, 0o644)
	os.WriteFile(filepath.Join(dir, "Documents", "script.lua"), []byte("-- dumped with eulen\nlocal x = 1"), 0o644)
	os.WriteFile(filepath.Join(dir, "Documents", "receita.txt"), []byte("bolo de cenoura com cobertura"), 0o644)
	os.WriteFile(filepath.Join(dir, "Documents", "scanner-PC-20260909-195039.txt"), []byte("eulen redengine susano"), 0o644)
	os.WriteFile(filepath.Join(dir, "Documents", "foto.jpg"), []byte("eulen dentro de imagem"), 0o644)

	a := assinaturasDeTeste(t)
	res := varrerConteudo(a, []string{dir}, time.Minute, 1<<30, nil)
	r := relatorioDeTeste()
	c := &Contexto{R: r, A: a}
	relatarConteudo(c, res)

	if !temAchado(r, Critico, "update.exe") {
		t.Errorf("nao detectou redengine em utf16 no exe: %+v", r.Achados)
	}
	if !temAchado(r, Critico, "script.lua") {
		t.Errorf("nao detectou eulen no lua: %+v", r.Achados)
	}
	for _, proibido := range []string{"receita.txt", "scanner-PC-20260909-195039.txt", "foto.jpg"} {
		if temAchado(r, Critico, proibido) || temAchado(r, Alerta, proibido) {
			t.Errorf("%s nao devia ser flagrado: %+v", proibido, r.Achados)
		}
	}
}

func TestPalavraWebRespeitaBordas(t *testing.T) {
	a := assinaturasDeTeste(t)
	if a.PalavraWeb("https://news.ycombinator.com/ Hacker News") != "" {
		t.Errorf("Hacker News nao devia casar")
	}
	if a.PalavraWeb("https://lifehacker.com/artigo") != "" {
		t.Errorf("lifehacker nao devia casar")
	}
	if a.PalavraWeb("melhor cheat pra fivem") == "" {
		t.Errorf("cheat devia casar")
	}
}

func TestNomesLegitimosNaoCasamComAssinaturas(t *testing.T) {
	a := assinaturasDeTeste(t)
	for _, nome := range []string{"DBDownloader.exe", "log-uploader.exe", "SenseSampleUploader.exe", "ghidraClean.bat", "SettingInjectorService.java", "InsetsAnimationThreadControlRunner.java", "NlsData0000.dll", "PlatformSpoofer", "draft5.gg/equipe/773-Vitality", "xercesImpl.jar DTDLoader"} {
		if classe, termo := a.Classificar(nome); classe != SemMatch {
			t.Errorf("%s nao devia casar (casou com %q)", nome, termo)
		}
		if termo := a.Dominio(nome); termo != "" {
			t.Errorf("%s nao devia casar com dominio %q", nome, termo)
		}
	}
	for _, nome := range []string{"eulen_loader.exe", "EULEN.EXE-1A2B3C4D.pf", "password_is_eulen.rar", "susano_loader.exe", "kdmapper.exe", "fivemcheats.exe"} {
		if classe, _ := a.Classificar(nome); classe != ClasseCheat {
			t.Errorf("%s devia casar como cheat", nome)
		}
	}
}

func TestNomeAleatorioNaoPegaDllDoWindows(t *testing.T) {
	for _, nome := range []string{"NlsData0000.dll", "SortServer2003Compat.dll", "kerb3961kernel.sys", "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"} {
		if pareceNomeAleatorio(nome) {
			t.Errorf("%s nao e aleatorio", nome)
		}
	}
	for _, nome := range []string{"a9f31c7d4b.exe", "3f8a1c9e2b7d.dll", "kmxtqzprwvbn12.sys"} {
		if !pareceNomeAleatorio(nome) {
			t.Errorf("%s devia ser aleatorio", nome)
		}
	}
}

func TestBuscadorIgnoraLixoBinario(t *testing.T) {
	b := NovoBuscador([]string{"eulen", "fivem cheat"})
	lixo := []byte("\x8f\x01eulen\xff\x02 ... \x00fivem cheats\x00 ... texto normal com eulen aqui")
	var termos []string
	b.Procurar(lixo, func(o Ocorrencia) bool { termos = append(termos, o.Termo); return true })
	if len(termos) != 2 {
		t.Fatalf("esperava 2 ocorrencias legiveis (fivem cheats com plural e eulen em texto), veio %v", termos)
	}
}

func TestNavegacaoIgnoraYoutubeEAntiCheat(t *testing.T) {
	a := assinaturasDeTeste(t)
	r := relatorioDeTeste()
	c := &Contexto{R: r, A: a, Instalacao: time.Now().Add(-90 * 24 * time.Hour)}
	agora := time.Now()
	registros := []registroNavegacao{
		{"Chrome", "visita", "https://www.youtube.com/shorts/abc", "(1784) Cheater or just the GOAT? #cs2", agora},
		{"Chrome", "visita", "https://www.youtube.com/shorts/def", "Genuinely aimbot?? #cs2 #faceit", agora},
		{"Chrome", "visita", "https://vac-ban.com/vacnet", "VACnet - Valve's AI Anti-Cheat", agora},
		{"Chrome", "visita", "https://draft5.gg/equipe/773-Vitality", "Vitality | DRAFT5", agora},
		{"Chrome", "download", "https://acupdate.gamersclub.com.br/download", `C:\Users\x\Downloads\Gamers Club Anti-Cheat Setup.exe`, agora},
		{"Chrome", "busca", "", "executor", agora},
		{"Chrome", "busca", "", "eulen fivem", agora},
		{"Chrome", "visita", "https://www.youtube.com/watch?v=zzz", "FiveM Aimbot ESP 2026 undetected", agora},
	}
	for i := 0; i < 40; i++ {
		registros = append(registros, registroNavegacao{"Chrome", "visita", fmt.Sprintf("https://site%d.com/", i), "pagina", agora.Add(-time.Duration(i) * 24 * time.Hour)})
	}
	relatarNavegacao(c, "dom", "Chrome", registros)
	for _, proibido := range []string{"cheater", "vitality", "anti-cheat setup", "vacnet"} {
		if temAchado(r, Critico, proibido) || temAchado(r, Alerta, proibido) {
			t.Errorf("%s nao devia ser flagrado: %+v", proibido, r.Achados)
		}
	}
	if !temAchado(r, Critico, "eulen") {
		t.Errorf("pesquisa por eulen devia ser critica: %+v", r.Achados)
	}
	if !temAchado(r, Critico, "FiveM Aimbot") {
		t.Errorf("video de aimbot fivem devia ser critico: %+v", r.Achados)
	}
	if !temAchado(r, Alerta, "executor") {
		t.Errorf("pesquisa 'executor' devia ser alerta: %+v", r.Achados)
	}
}

func TestComandosDeOcultacaoNaoPegamScriptsNormais(t *testing.T) {
	for _, cmd := range []string{
		`Select-String -Path "D:\x\mapper\AitResultAssemblerTest.java" -Pattern "@Test"`,
		`= 'In'; Value = $__cmdletization_defaultValue; Set-MpPreference DisableRealtimeMonitoring`,
		`Get-ChildItem C:\Windows\Prefetch`,
		`prefetch`,
	} {
		if motivo := comandoDeOcultacao(cmd); motivo != "" && !scriptDoSistemaOuDoScanner(cmd) {
			t.Errorf("%q nao devia ser ocultacao (%s)", cmd, motivo)
		}
	}
	for _, cmd := range []string{
		`wevtutil cl Security`,
		`Set-MpPreference -DisableRealtimeMonitoring $true`,
		`Remove-Item C:\Windows\Prefetch\* -Force`,
		`fsutil usn deletejournal /d C:`,
		`kdmapper.exe driver.sys`,
	} {
		if comandoDeOcultacao(cmd) == "" {
			t.Errorf("%q devia ser ocultacao", cmd)
		}
	}
}

func TestVarreduraProfundaDoNavegador(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "Network"), 0o755)

	cookies, err := sql.Open("sqlite", filepath.Join(dir, "Network", "Cookies"))
	if err != nil {
		t.Fatal(err)
	}
	cookies.Exec(`CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT)`)
	cookies.Exec(`INSERT INTO cookies VALUES(13400000000000000,'.eulen.cc','session')`)
	cookies.Exec(`INSERT INTO cookies VALUES(13400000000000000,'.discord.gg','token')`)
	cookies.Exec(`INSERT INTO cookies VALUES(13400000000000000,'.globo.com','ga')`)
	cookies.Close()

	logins, err := sql.Open("sqlite", filepath.Join(dir, "Login Data"))
	if err != nil {
		t.Fatal(err)
	}
	logins.Exec(`CREATE TABLE logins(origin_url TEXT, username_value TEXT, date_created INTEGER)`)
	logins.Exec(`INSERT INTO logins VALUES('https://eulen.cc/login','jogador_br',13400000000000000)`)
	logins.Exec(`INSERT INTO logins VALUES('https://mail.google.com/','dom',13400000000000000)`)
	logins.Close()

	atalhos, err := sql.Open("sqlite", filepath.Join(dir, "Shortcuts"))
	if err != nil {
		t.Fatal(err)
	}
	atalhos.Exec(`CREATE TABLE omni_box_shortcuts(url TEXT, text TEXT, last_access_time INTEGER)`)
	atalhos.Exec(`INSERT INTO omni_box_shortcuts VALUES('https://ghostmenu.cc/','ghost menu',13400000000000000)`)
	atalhos.Exec(`INSERT INTO omni_box_shortcuts VALUES('https://www.youtube.com/','youtube',13400000000000000)`)
	atalhos.Close()

	os.WriteFile(filepath.Join(dir, "Bookmarks"), []byte(`{"roots":{"bookmark_bar":{"children":[
	 {"name":"Ghost Menu | Discord","type":"url","url":"https://discord.gg/ghostmenu"},
	 {"name":"Cidade Alta","type":"url","url":"https://cidadealta.com.br/"}]}}}`), 0o644)

	os.MkdirAll(filepath.Join(dir, "Extensions", "abcdefg", "1.0"), 0o755)
	os.WriteFile(filepath.Join(dir, "Extensions", "abcdefg", "1.0", "manifest.json"), []byte(`{"name":"uBlock Origin","description":"bloqueador"}`), 0o644)

	os.WriteFile(filepath.Join(dir, "Current Tabs"), append([]byte("SNSS\x01\x00\x00\x00lixo"), []byte("https://eulen.cc/dashboard\x00mais lixo")...), 0o644)

	r := relatorioDeTeste()
	c := &Contexto{R: r, A: assinaturasDeTeste(t)}
	varreduraProfundaDoNavegador(c, "jogador", "Chrome", filepath.Join(dir, "History"), "chromium")

	if !temAchado(r, Critico, "CONTA SALVA em site de cheat ('eulen.cc')") {
		t.Errorf("nao detectou conta salva no eulen: %+v", r.Achados)
	}
	if !temAchado(r, Critico, "cookie de 'eulen.cc'") {
		t.Errorf("nao detectou cookie do eulen: %+v", r.Achados)
	}
	if !temAchado(r, Critico, "ghostmenu") && !temAchado(r, Critico, "ghost menu") {
		t.Errorf("nao detectou favorito/omnibox do ghost menu: %+v", r.Achados)
	}
	if !temAchado(r, Critico, "aba aberta") {
		t.Errorf("nao detectou aba com eulen: %+v", r.Achados)
	}
	for _, limpo := range []string{"globo.com", "mail.google.com", "cidadealta", "uBlock", "youtube"} {
		if temAchado(r, Critico, limpo) || temAchado(r, Alerta, limpo) {
			t.Errorf("%s nao devia ser flagrado: %+v", limpo, r.Achados)
		}
	}
}

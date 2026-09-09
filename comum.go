package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

func caminhoSuspeito(caminho string) string {
	c := strings.ToLower(caminho)
	base := nomeBase(caminho)
	if strings.HasPrefix(strings.ToLower(base), "scanner") {
		return ""
	}
	switch {
	case strings.Contains(c, `\$recycle.bin\`):
		return "rodado de dentro da LIXEIRA"
	case (strings.Contains(c, `\appdata\local\temp\`) || strings.Contains(c, `\windows\temp\`)) && pareceNomeAleatorio(base):
		return "com nome aleatorio rodado da pasta TEMP"
	case strings.Contains(c, `\users\public\`) && strings.HasSuffix(c, ".exe"):
		return "rodado da pasta Publica"
	}
	if pareceNomeAleatorio(base) {
		return "com nome aleatorio"
	}
	return ""
}

func pareceInstalador(caminho string) bool {
	base := strings.ToLower(nomeBase(caminho))
	for _, marca := range []string{"setup", "install", "update", "launcher", "driver", "redist", "vc_", "dotnet", "runtime", "webview"} {
		if strings.Contains(base, marca) {
			return true
		}
	}
	return false
}

func pareceNomeAleatorio(nome string) bool {
	ext := strings.ToLower(filepath.Ext(nome))
	if ext != ".exe" && ext != ".dll" && ext != ".sys" {
		return false
	}
	base := strings.ToLower(strings.TrimSuffix(nome, filepath.Ext(nome)))
	if len(base) < 8 {
		return false
	}
	hex, letras, digitos, vogais := true, 0, 0, 0
	for _, ch := range base {
		switch {
		case ch >= '0' && ch <= '9':
			digitos++
		case ch >= 'a' && ch <= 'z':
			letras++
			if strings.ContainsRune("aeiouy", ch) {
				vogais++
			}
			if ch > 'f' {
				hex = false
			}
		default:
			return false
		}
	}
	if hex && digitos >= 3 && letras >= 1 {
		return true
	}
	return len(base) >= 12 && vogais == 0 && digitos >= 2
}

var padroesOcultacao = []struct {
	re     *regexp.Regexp
	motivo string
}{
	{regexp.MustCompile(`(?i)wevtutil\s+(cl|clear-log)`), "limpa log de eventos"},
	{regexp.MustCompile(`(?i)clear-eventlog`), "limpa log de eventos"},
	{regexp.MustCompile(`(?i)limit-eventlog`), "mexe no tamanho do log"},
	{regexp.MustCompile(`(?i)fsutil\s+usn\s+deletejournal`), "apaga o journal USN"},
	{regexp.MustCompile(`(?i)(remove-item|del |rd |rmdir |erase |clear-content).*prefetch`), "apaga o Prefetch"},
	{regexp.MustCompile(`(?i)(sc|net)(\.exe)?\s+(stop|config|delete)\s+(eventlog|sysmain|pcasvc|dps|dnscache|windefend|diagtrack|bam|wsearch|schedule)`), "para servico de rastreio"},
	{regexp.MustCompile(`(?i)stop-service.*(eventlog|sysmain|pcasvc|dps|dnscache|windefend|diagtrack|bam)`), "para servico de rastreio"},
	{regexp.MustCompile(`(?i)set-mppreference\s+-disable\w*\s+(\$true|1)`), "desliga o Defender"},
	{regexp.MustCompile(`(?i)add-mppreference\s+-exclusion`), "adiciona exclusao no Defender"},
	{regexp.MustCompile(`(?i)disableantispyware|disablerealtimemonitoring`), "desliga o Defender"},
	{regexp.MustCompile(`(?i)bcdedit.*(testsigning|nointegritychecks|debug)`), "habilita drivers sem assinatura"},
	{regexp.MustCompile(`(?i)(remove-item|reg delete|remove-itemproperty|del ).*(userassist|muicache|recentdocs|runmru|typedpaths|wordwheelquery|shellbag|compatibility assistant|\\bam\\)`), "limpa historico do registro"},
	{regexp.MustCompile(`(?i)clear-recyclebin`), "esvazia lixeira por script"},
	{regexp.MustCompile(`(?i)ipconfig\s*/flushdns`), "limpa cache DNS"},
	{regexp.MustCompile(`(?i)vssadmin\s+delete\s+shadows`), "apaga pontos de restauracao"},
	{regexp.MustCompile(`(?i)cipher\s+/w`), "sobrescreve espaco livre"},
	{regexp.MustCompile(`(?i)sdelete`), "apaga arquivo de forma irrecuperavel"},
	{regexp.MustCompile(`(?i)kdmapper|drvmap|kdmap\b`), "mapeador de driver"},
}

func scriptDoSistemaOuDoScanner(texto string) bool {
	t := strings.ToLower(texto)
	for _, marca := range []string{
		"__cmdletization", "$script:mymodule", "#requires -version 3.0",
		"get-mpcomputerstatus | select-object", "get-mppreference | select-object", "get-mpthreat | select-object",
		"[parameter(parametersetname=", "[validatenotnull", "[validatenotnullorempty", "[cmdletbinding(",
		"[microsoft.powershell.cmdletization", "generatedtypes.mppreference", "new-object system.management.automation.parametermetadata",
		"[system.management.automation.aliasattribute", "$psboundparameters", "dynamicparam {", "cmdletization.generatedtypes",
	} {
		if strings.Contains(t, marca) {
			return true
		}
	}
	return false
}

func comandoDeOcultacao(texto string) string {
	for _, p := range padroesOcultacao {
		if p.re.MatchString(texto) {
			return p.motivo
		}
	}
	return ""
}

func limita(linhas []string, max int) []string {
	if len(linhas) <= max {
		return linhas
	}
	return append(linhas[:max], fmt.Sprintf("... e mais %d", len(linhas)-max))
}

func resume(texto string, max int) string {
	texto = strings.Join(strings.Fields(texto), " ")
	if len(texto) > max {
		return texto[:max] + "..."
	}
	return texto
}

func nomeBase(caminho string) string {
	caminho = strings.Trim(caminho, `"`)
	if i := strings.LastIndexAny(caminho, `\/`); i >= 0 {
		caminho = caminho[i+1:]
	}
	if i := strings.Index(caminho, " "); i > 0 && strings.Contains(strings.ToLower(caminho[:i]), ".") {
		caminho = caminho[:i]
	}
	return caminho
}

func listaDeQualquer(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var s []string
		for _, i := range t {
			if str, ok := i.(string); ok {
				s = append(s, str)
			}
		}
		return s
	}
	return nil
}

func objetosDeQualquer(v any) []map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return []map[string]any{t}
	case []any:
		var s []map[string]any
		for _, i := range t {
			if m, ok := i.(map[string]any); ok {
				s = append(s, m)
			}
		}
		return s
	}
	return nil
}

func pastaDeDesenvolvimento(caminho string) bool {
	for _, marca := range []string{"jetbrains", "intellij", "webstorm", "pycharm", "rider", "vscode", "visual studio", "projetos", "projects", `\src\`, `\repos`, "github", "gitlab", "node_modules", `\sdk`, "android", "flutter", "docker", `\wsl`, "unity", "unreal", `\dev\`, `\workspace`, `\go\`, `\rust`, `\.cargo`, `\.nuget`, `\.gradle`, `\.m2`, "xampp", "laragon", "wamp"} {
		if strings.Contains(caminho, marca) {
			return true
		}
	}
	return false
}

func nomeDeBackupOuTemporario(nome, caminho string) bool {
	n := strings.ToLower(nome)
	for _, marca := range []string{".exe.", ".dll.", ".sys.", ".msi.", "~", ".partial", ".crdownload", ".download"} {
		if strings.Contains(n, marca) {
			return true
		}
	}
	if strings.HasSuffix(n, ".tmp") && strings.Contains(strings.ToLower(caminho), `\temp\`) {
		return true
	}
	return false
}

func extensaoDeTexto(nome string) bool {
	for _, ext := range []string{".vim", ".md", ".txt", ".json", ".xml", ".yml", ".yaml", ".cfg", ".ini", ".csv", ".log", ".rst", ".html", ".css", ".java", ".py", ".ts", ".c", ".h", ".cpp", ".go", ".rb", ".php"} {
		if strings.HasSuffix(strings.ToLower(nome), ext) {
			return true
		}
	}
	return false
}

func pacoteDeDriverOuInstalador(caminho string) bool {
	c := strings.ToLower(caminho)
	for _, marca := range []string{`\driver`, `\drivers\`, `_win7_`, `_win10`, `_win81`, `\win64\`, `\win32\`, `\x64\`, `\tool\`,
		`realtek`, `nvidia`, `\amd\`, `intel`, `\install_`, `\setup`, `installer`, `redist`, `\bin\`, `\sdk\`, `\runtime`} {
		if strings.Contains(c, marca) {
			return true
		}
	}
	return false
}

func arquivoDoProprioJogo(caminho string) bool {
	c := strings.ToLower(caminho)
	for _, marca := range []string{`\fivem.app\`, `\citizenfx\`, `\cfx\`, `\rockstar games\`, `\grand theft auto v\`, `\steamapps\`, `\epic games\`} {
		if strings.Contains(c, marca) {
			return true
		}
	}
	return false
}

var cp1252Alto = []rune{
	'\u20ac', '\u0081', '\u201a', '\u0192', '\u201e', '\u2026', '\u2020', '\u2021',
	'\u02c6', '\u2030', '\u0160', '\u2039', '\u0152', '\u008d', '\u017d', '\u008f',
	'\u0090', '\u2018', '\u2019', '\u201c', '\u201d', '\u2022', '\u2013', '\u2014',
	'\u02dc', '\u2122', '\u0161', '\u203a', '\u0153', '\u009d', '\u017e', '\u0178',
}

func paraUTF8(texto string) string {
	if utf8.ValidString(texto) {
		return texto
	}
	var b strings.Builder
	b.Grow(len(texto))
	for i := 0; i < len(texto); i++ {
		c := texto[i]
		if c < 0x80 {
			b.WriteByte(c)
			continue
		}
		if r, tam := utf8.DecodeRuneInString(texto[i:]); r != utf8.RuneError {
			b.WriteRune(r)
			i += tam - 1
			continue
		}
		if c < 0xa0 {
			b.WriteRune(cp1252Alto[c-0x80])
		} else {
			b.WriteRune(rune(c))
		}
	}
	return b.String()
}

func ehSiteDeCompartilhamento(url string) string {
	u := strings.ToLower(url)
	for _, site := range []string{"mediafire.com", "anonfiles", "pixeldrain", "gofile.io", "mega.nz", "mega.io", "1fichier",
		"drive.google.com", "drive.usercontent.google.com", "dropbox.com", "wetransfer", "sendspace", "zippyshare",
		"cdn.discordapp.com", "media.discordapp.net", "workupload", "krakenfiles", "bowfile", "filecrypt", "up-4.net",
		"userscloud", "racaty", "file-upload", "dosya.co", "fastupload", "uploadhaven", "buzzheavier"} {
		if strings.Contains(u, site) {
			return site
		}
	}
	return ""
}

func arquivoDoUniversoDoJogo(nome string) string {
	n := strings.ToLower(nome)
	for _, ext := range []string{".mp4", ".mkv", ".avi", ".mov", ".webm", ".gif", ".png", ".jpg", ".jpeg", ".mp3", ".wav", ".txt", ".pdf", ".docx", ".xlsx",
		".xml", ".cfg", ".ini", ".json", ".yml", ".yaml", ".log", ".csv", ".md", ".meta", ".sql"} {
		if strings.HasSuffix(n, ext) {
			return ""
		}
	}
	for _, marca := range []string{"citizen", "fivem", "cfx", "gta", "rage", "scripthook", "asi", "dinput8", "d3d11", "dxgi", "openiv", "rph", "ragehook"} {
		if strings.Contains(n, marca) {
			return marca
		}
	}
	return ""
}

func contaDeServicoDoWindows(usuario string) bool {
	u := strings.ToLower(strings.TrimSpace(usuario))
	for _, conta := range []string{"local service", "servi", "network service", "servico de rede", "system", "sistema", "nt authority", "autoridade nt", "local system"} {
		if strings.Contains(u, conta) {
			return true
		}
	}
	return false
}

func primeiraParte(titulo string) string {
	if i := strings.Index(titulo, ":"); i > 0 {
		return titulo[:i]
	}
	return titulo
}

var reCaminhoWindows = regexp.MustCompile(`[A-Za-z]:\\[^\r\n"'<>|*?]+`)

var sufixosDeCorte = []string{"  ", "\t", " <- ", " -> ", " (deletado", " (registrado", " (bate com", " (%s)"}

func limpaCaminho(bruto string) string {
	c := strings.TrimSpace(bruto)
	for _, corte := range sufixosDeCorte {
		if i := strings.Index(c, corte); i > 3 {
			c = c[:i]
		}
	}
	c = strings.TrimSpace(c)
	if i := strings.LastIndex(c, "  "); i > 3 {
		c = c[:i]
	}
	c = strings.TrimRight(c, " .,;:]}'\"")
	for strings.HasSuffix(c, ")") && strings.Count(c, ")") > strings.Count(c, "(") {
		c = strings.TrimSuffix(c, ")")
		c = strings.TrimRight(c, " .,;:")
	}
	if len(c) < 4 || !strings.Contains(c, `\`) {
		return ""
	}
	return c
}

func caminhosNoTexto(textos ...string) []string {
	var saida []string
	vistos := map[string]bool{}
	for _, texto := range textos {
		for _, linha := range strings.Split(texto, "\n") {
			for _, bruto := range reCaminhoWindows.FindAllString(linha, -1) {
				c := limpaCaminho(bruto)
				if c == "" {
					continue
				}
				chave := strings.ToLower(c)
				if vistos[chave] {
					continue
				}
				vistos[chave] = true
				saida = append(saida, c)
				if len(saida) >= 8 {
					return saida
				}
			}
		}
	}
	return saida
}

func driverDeAnticheatConhecido(nome string) bool {
	n := strings.ToLower(nome)
	for _, marca := range []string{"vgk.sys", "vgc.sys", "easyanticheat", "eac", "beDaisy", "bedaisy.sys", "battleye", "faceit", "gcac", "mhyprot", "ntiolib", "esea"} {
		if strings.HasPrefix(n, strings.ToLower(marca)) || n == strings.ToLower(marca) {
			return true
		}
	}
	return false
}

func estourouOTempo(inicio time.Time, limite time.Duration) bool {
	return limite > 0 && time.Since(inicio) > limite
}

func estourouOTamanho(lidos, limite int64) bool {
	return limite > 0 && lidos > limite
}

func descreveLimite(limite time.Duration) string {
	if limite <= 0 {
		return "sem limite de tempo"
	}
	return "limite de " + limite.Round(time.Second).String()
}

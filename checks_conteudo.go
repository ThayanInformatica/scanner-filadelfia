package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var extensoesIgnoradasNoConteudo = map[string]bool{
	".mp4": true, ".mkv": true, ".avi": true, ".mov": true, ".webm": true, ".mp3": true, ".wav": true, ".flac": true,
	".ogg": true, ".m4a": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".bmp": true,
	".ico": true, ".psd": true, ".iso": true, ".vhd": true, ".vhdx": true, ".vmdk": true, ".pak": true, ".rpf": true,
	".ytd": true, ".ydr": true, ".yft": true, ".ymap": true, ".ybn": true, ".ydd": true, ".awc": true, ".bik": true,
	".ttf": true, ".otf": true, ".woff": true, ".woff2": true, ".pdf": true, ".docx": true, ".xlsx": true, ".pptx": true,
	".pf": true, ".db": true, ".sqlite": true, ".ldb": true, ".jar": true, ".zip": true, ".rar": true, ".7z": true,
	".gz": true, ".xz": true, ".bz2": true, ".whl": true, ".nupkg": true, ".apk": true, ".aab": true, ".war": true,
	".class": true, ".pyc": true, ".wasm": true, ".map": true, ".pdb": true, ".lib": true, ".obj": true, ".o": true,
}

var extensoesExecutaveisOuScripts = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".asi": true, ".lua": true, ".bat": true, ".cmd": true, ".ps1": true,
	".vbs": true, ".js": true, ".py": true, ".ahk": true, ".scr": true, ".com": true, ".jar": true,
}

var trechosIgnoradosNoConteudo = []string{
	`\perl\lib\unicore\`, `\postgres\data\`, `\postgresql\data\`, `\pgsql\data\`, `\pg_data\`,
	`\google\chrome\`, `\microsoft\edge\`, `\bravesoftware\`, `\vivaldi\`, `\opera software\`, `\mozilla\firefox\`,
	`\discord\`, `\discordcanary\`, `\discordptb\`, `\fivem\fivem.app\data\cache\`, `\fivem\fivem.app\citizen\`,
	`\fivem\fivem.app\bin\`, `\node_modules\`, `\.git\`, `\steam\steamapps\`, `\epic games\`, `\rockstar games\`,
	`\windows\`, `\program files\`, `\program files (x86)\`, `\microsoft\windowsapps\`, `\packages\`,
	`\code cache\`, `\gpucache\`, `\cachestorage\`, `\indexeddb\`, `\service worker\`,
}

type achadoConteudo struct {
	Caminho    string
	Termos     []string
	Contexto   string
	Extensao   string
	Modificado time.Time
	Tamanho    int64
}

type resultadoConteudo struct {
	Arquivos     int
	Bytes        int64
	Achados      []achadoConteudo
	Interrompido bool
}

func ignorarNoConteudo(caminho string, a *Assinaturas) bool {
	lower := strings.ToLower(caminho)
	base := filepath.Base(lower)
	if arquivoDeRelatorioDoScanner(base) || base == "assinaturas.json" || base == "assinaturas.exemplo.json" || ehCopiaDoScanner(caminho) || arquivoDoProprioKit(caminho) {
		return true
	}
	for _, t := range trechosIgnoradosNoConteudo {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return a.Ignorar(lower)
}

type informaProgresso func(arquivos int, bytes int64, atual string)

func varrerConteudo(a *Assinaturas, raizes []string, limite time.Duration, limiteBytes int64, progresso informaProgresso) resultadoConteudo {
	return varrerConteudoCancelavel(a, raizes, limite, limiteBytes, progresso, nil)
}

func varrerConteudoCancelavel(a *Assinaturas, raizes []string, limite time.Duration, limiteBytes int64, progresso informaProgresso, cancelar func() bool) resultadoConteudo {
	res := resultadoConteudo{}
	buscador := NovoBuscador(a.TermosParaConteudo())
	inicio := time.Now()
	vistos := map[string]bool{}
	ultimoAviso := time.Now()

	type candidato struct {
		caminho string
		ext     string
		info    fs.FileInfo
	}
	fila := make(chan candidato, 4096)
	var mu sync.Mutex
	var arquivosLidos int64
	var bytesLidos int64
	var wg sync.WaitGroup
	trabalhadores := runtime.NumCPU()
	if trabalhadores > 8 {
		trabalhadores = 8
	}
	if trabalhadores < 2 {
		trabalhadores = 2
	}
	for i := 0; i < trabalhadores; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 0, 4*1024*1024)
			for c := range fila {
				dados, ok := lerArquivoInteiro(c.caminho, c.info.Size(), &buf)
				if !ok {
					continue
				}
				atomic.AddInt64(&arquivosLidos, 1)
				atomic.AddInt64(&bytesLidos, int64(len(dados)))
				if extensoesIgnoradasNoConteudo[c.ext] && !comecaComMZ(dados) {
					continue
				}
				termos := map[string]bool{}
				contexto := ""
				buscador.Procurar(dados, func(o Ocorrencia) bool {
					if !termos[o.Termo] {
						termos[o.Termo] = true
						if contexto == "" {
							contexto = trechoEmVolta(dados, o.Inicio, o.Fim, o.UTF16)
						}
					}
					return len(termos) < 6
				})
				if len(termos) == 0 {
					continue
				}
				var lista []string
				for t := range termos {
					lista = append(lista, t)
				}
				sort.Strings(lista)
				mu.Lock()
				res.Achados = append(res.Achados, achadoConteudo{Caminho: c.caminho, Termos: lista, Contexto: contexto, Extensao: c.ext, Modificado: c.info.ModTime(), Tamanho: c.info.Size()})
				mu.Unlock()
			}
		}()
	}

	for _, raiz := range raizes {
		if raiz == "" || !existe(raiz) {
			continue
		}
		filepath.WalkDir(raiz, func(caminho string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if estourouOTempo(inicio, limite) || estourouOTamanho(atomic.LoadInt64(&bytesLidos), limiteBytes) || (cancelar != nil && cancelar()) {
				res.Interrompido = true
				return filepath.SkipAll
			}
			if progresso != nil && time.Since(ultimoAviso) > 1500*time.Millisecond {
				ultimoAviso = time.Now()
				progresso(int(atomic.LoadInt64(&arquivosLidos)), atomic.LoadInt64(&bytesLidos), filepath.Dir(caminho))
			}
			if d.IsDir() {
				if caminho != raiz && ignorarNoConteudo(caminho+string(os.PathSeparator), a) {
					return filepath.SkipDir
				}
				return nil
			}
			lower := strings.ToLower(caminho)
			if vistos[lower] || ignorarNoConteudo(caminho, a) {
				return nil
			}
			vistos[lower] = true
			ext := strings.ToLower(filepath.Ext(caminho))
			if extensoesIgnoradasNoConteudo[ext] && !extensaoQuePodeEsconderPrograma[ext] {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() == 0 || info.Size() > 30*1024*1024 {
				return nil
			}
			fila <- candidato{caminho: caminho, ext: ext, info: info}
			return nil
		})
	}
	close(fila)
	wg.Wait()
	res.Arquivos = int(arquivosLidos)
	res.Bytes = bytesLidos
	sort.Slice(res.Achados, func(i, j int) bool { return res.Achados[i].Caminho < res.Achados[j].Caminho })
	return res
}

var extensaoQuePodeEsconderPrograma = map[string]bool{
	".rpf": true, ".ytd": true, ".ydr": true, ".yft": true, ".ymap": true, ".ybn": true, ".ydd": true, ".awc": true,
	".pak": true, ".db": true, ".ldb": true, ".pdb": true, ".lib": true, ".obj": true, ".o": true, ".map": true, ".bik": true,
}

func comecaComMZ(dados []byte) bool {
	return len(dados) > 2 && dados[0] == 'M' && dados[1] == 'Z'
}

func lerArquivoInteiro(caminho string, tamanho int64, buf *[]byte) ([]byte, bool) {
	f, err := os.Open(caminho)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if real, err := f.Stat(); err == nil {
		if real.IsDir() || real.Size() > 30*1024*1024 {
			return nil, false
		}
		tamanho = real.Size()
	}
	if tamanho <= 0 {
		return nil, false
	}
	if int64(cap(*buf)) < tamanho {
		*buf = make([]byte, 0, tamanho+tamanho/4)
	}
	dados := (*buf)[:tamanho]
	n, err := io.ReadFull(f, dados)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, false
	}
	return dados[:n], true
}

func raizesParaConteudo(perfis []Perfil, extras []string) []string {
	var raizes []string
	for _, p := range perfis {
		for _, sub := range []string{"Desktop", "Downloads", "Documents", "Videos", "Pictures", "Music", "OneDrive", filepath.Join("AppData", "Local"), filepath.Join("AppData", "Roaming"), filepath.Join("AppData", "LocalLow")} {
			raizes = append(raizes, filepath.Join(p.Pasta, sub))
		}
	}
	raizes = append(raizes, `C:\Users\Public`, `C:\ProgramData`, `C:\Temp`, `C:\tmp`)
	raizes = append(raizes, extras...)
	for _, u := range unidadesFixas() {
		if !strings.EqualFold(u, `C:\`) {
			raizes = append(raizes, u)
		}
	}
	return raizes
}

func checarConteudo(c *Contexto) {
	r := c.R
	r.Secao("STRINGS DE CHEAT NO CONTEUDO DOS ARQUIVOS")
	if c.Rapido {
		r.Linha("Modo rapido: busca de strings pulada")
		return
	}
	raizes := raizesParaConteudo(c.Perfis, c.A.PastasExtra)
	inicio := time.Now()
	res := varrerConteudoCancelavel(c.A, raizes, c.LimiteEtapa, 0, func(arquivos int, bytes int64, atual string) {
		r.Progresso("%d arquivos lidos (%d MB) em %s. Agora em: %s", arquivos, bytes/1024/1024, time.Since(inicio).Round(time.Second), atual)
	}, c.DevePular)
	r.Linha("%d arquivos (%d MB) lidos em %s", res.Arquivos, res.Bytes/1024/1024, time.Since(inicio).Round(time.Second))
	if res.Interrompido {
		r.Add(Alerta, "BUSCA DE STRINGS INCOMPLETA: parou por limite", "Parte dos arquivos NAO foi lida. Rode de novo sem limite antes de concluir qualquer coisa sobre este PC")
	}
	relatarConteudo(c, res)
}

func relatarConteudo(c *Contexto, res resultadoConteudo) {
	r := c.R
	if len(res.Achados) == 0 {
		r.Ok("Nenhum arquivo com string de cheat no conteudo")
		return
	}
	sort.Slice(res.Achados, func(i, j int) bool {
		ei, ej := extensoesExecutaveisOuScripts[res.Achados[i].Extensao], extensoesExecutaveisOuScripts[res.Achados[j].Extensao]
		if ei != ej {
			return ei
		}
		return res.Achados[i].Modificado.After(res.Achados[j].Modificado)
	})
	emitidos := 0
	var restantes []string
	for _, a := range res.Achados {
		linha := fmt.Sprintf("%s  %d KB  %s", formataHora(a.Modificado), a.Tamanho/1024, a.Caminho)
		if emitidos >= 300 {
			restantes = append(restantes, linha)
			continue
		}
		emitidos++
		sev := Alerta
		tipo := "Arquivo"
		nota := ""
		if extensoesExecutaveisOuScripts[a.Extensao] {
			sev = Critico
			tipo = "Executavel/script"
		}
		if recursoDeServidorFiveM(a.Caminho, existe) {
			sev = Alerta
			nota = "\nEsta dentro de um recurso de servidor FiveM (tem fxmanifest.lua). Script de anticheat e de administracao cita nome de cheat por natureza. Vale olhar, mas nao e o padrao de cheat, que fica solto em Downloads ou Temp"
		} else if origem := dadosDeJogoInstalado(a.Caminho); origem != "" && !extensoesExecutaveisOuScripts[a.Extensao] {
			sev = Info
			nota = "\nArquivo de dados de " + origem + ". Palavra coincidente em texto de jogo, quase sempre"
		}
		titulo := fmt.Sprintf("%s contem string '%s'", tipo, a.Termos[0])
		if len(a.Termos) > 1 {
			titulo += fmt.Sprintf(" (+%d: %s)", len(a.Termos)-1, strings.Join(a.Termos[1:], ", "))
		}
		titulo += ": " + filepath.Base(a.Caminho)
		detalhe := linha
		if a.Contexto != "" {
			detalhe += "\n..." + a.Contexto + "..."
		}
		r.Add(sev, titulo, detalhe+nota)
	}
	if len(restantes) > 0 {
		r.Add(Alerta, fmt.Sprintf("Mais %d arquivo(s) com strings de cheat", len(restantes)), strings.Join(limitaLinhas(restantes, 160), "\n"))
	}
}

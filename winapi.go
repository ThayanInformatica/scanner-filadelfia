//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	psapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGetTickCount64    = kernel32.NewProc("GetTickCount64")
	procEnumDeviceDrivers = psapi.NewProc("EnumDeviceDrivers")
	procDriverFileName    = psapi.NewProc("GetDeviceDriverFileNameW")
)

const epocaFiletime = 116444736000000000

func filetimeParaTime(ft uint64) time.Time {
	if ft < epocaFiletime {
		return time.Time{}
	}
	return time.Unix(0, int64(ft-epocaFiletime)*100).Local()
}

func filetimeDeBytes(b []byte) time.Time {
	if len(b) < 8 {
		return time.Time{}
	}
	return filetimeParaTime(binary.LittleEndian.Uint64(b[:8]))
}

func utf16DeBytes(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

func rot13(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteRune('a' + (c-'a'+13)%26)
		case c >= 'A' && c <= 'Z':
			b.WriteRune('A' + (c-'A'+13)%26)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

func estaElevado() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func relancarElevado() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var partes []string
	for _, a := range os.Args[1:] {
		partes = append(partes, syscall.EscapeArg(a))
	}
	args := strings.Join(partes, " ")
	verbo, _ := syscall.UTF16PtrFromString("runas")
	arquivo, _ := syscall.UTF16PtrFromString(exe)
	argumentos, _ := syscall.UTF16PtrFromString(args)
	pasta, _ := syscall.UTF16PtrFromString(filepath.Dir(exe))
	return windows.ShellExecute(0, verbo, arquivo, argumentos, pasta, windows.SW_SHOWNORMAL)
}

func habilitarCoresConsole() bool {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return false
	}
	var modo uint32
	if err := windows.GetConsoleMode(h, &modo); err != nil {
		return false
	}
	return windows.SetConsoleMode(h, modo|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}

func tempoLigado() time.Duration {
	ms, _, _ := procGetTickCount64.Call()
	return time.Duration(ms) * time.Millisecond
}

func executar(nome string, args ...string) (string, error) {
	cmd := exec.Command(nome, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var saida, erro bytes.Buffer
	cmd.Stdout = &saida
	cmd.Stderr = &erro
	err := cmd.Run()
	texto := paraUTF8(saida.String())
	if err != nil && texto == "" {
		return "", fmt.Errorf("%s: %v %s", nome, err, strings.TrimSpace(erro.String()))
	}
	return texto, nil
}

func powershell(script string) (string, error) {
	return executar("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

type Processo struct {
	PID     uint32
	PaiPID  uint32
	Nome    string
	Caminho string
}

func listarProcessos() ([]Processo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var lista []Processo
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		p := Processo{PID: pe.ProcessID, PaiPID: pe.ParentProcessID, Nome: windows.UTF16ToString(pe.ExeFile[:])}
		p.Caminho = caminhoDoProcesso(p.PID)
		lista = append(lista, p)
	}
	return lista, nil
}

func caminhoDoProcesso(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	tam := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &tam); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:tam])
}

type Modulo struct {
	Nome    string
	Caminho string
}

func listarModulos(pid uint32) ([]Modulo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	var lista []Modulo
	for err = windows.Module32First(snap, &me); err == nil; err = windows.Module32Next(snap, &me) {
		lista = append(lista, Modulo{Nome: windows.UTF16ToString(me.Module[:]), Caminho: windows.UTF16ToString(me.ExePath[:])})
	}
	return lista, nil
}

func listarDrivers() ([]string, error) {
	var necessario uint32
	procEnumDeviceDrivers.Call(0, 0, uintptr(unsafe.Pointer(&necessario)))
	if necessario == 0 {
		return nil, fmt.Errorf("EnumDeviceDrivers nao retornou nada")
	}
	bases := make([]uintptr, necessario/uint32(unsafe.Sizeof(uintptr(0)))+1)
	ok, _, err := procEnumDeviceDrivers.Call(uintptr(unsafe.Pointer(&bases[0])), uintptr(necessario), uintptr(unsafe.Pointer(&necessario)))
	if ok == 0 {
		return nil, err
	}
	total := int(necessario / uint32(unsafe.Sizeof(uintptr(0))))
	var lista []string
	buf := make([]uint16, 1024)
	for i := 0; i < total && i < len(bases); i++ {
		n, _, _ := procDriverFileName.Call(bases[i], uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n > 0 {
			lista = append(lista, windows.UTF16ToString(buf[:n]))
		}
	}
	return lista, nil
}

const (
	ciEnabled   = 0x01
	ciTestSign  = 0x02
	ciDebugMode = 0x08
)

func integridadeDeCodigo() (uint32, error) {
	var info struct {
		Tamanho uint32
		Opcoes  uint32
	}
	info.Tamanho = uint32(unsafe.Sizeof(info))
	var ret uint32
	if err := windows.NtQuerySystemInformation(103, unsafe.Pointer(&info), info.Tamanho, &ret); err != nil {
		return 0, err
	}
	return info.Opcoes, nil
}

func unidadesFixas() []string {
	mascara, err := windows.GetLogicalDrives()
	if err != nil {
		return []string{"C:\\"}
	}
	var lista []string
	for i := 0; i < 26; i++ {
		if mascara&(1<<i) == 0 {
			continue
		}
		raiz := string(rune('A'+i)) + ":\\"
		p, _ := syscall.UTF16PtrFromString(raiz)
		if windows.GetDriveType(p) == windows.DRIVE_FIXED {
			lista = append(lista, raiz)
		}
	}
	return lista
}

func lerDword(raiz registry.Key, caminho, nome string) (uint64, bool) {
	k, err := registry.OpenKey(raiz, caminho, registry.READ)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(nome)
	if err != nil {
		return 0, false
	}
	return v, true
}

func lerString(raiz registry.Key, caminho, nome string) (string, bool) {
	k, err := registry.OpenKey(raiz, caminho, registry.READ)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(nome)
	if err != nil {
		return "", false
	}
	if expandido, err := registry.ExpandString(v); err == nil {
		return expandido, true
	}
	return v, true
}

func nomesDeValores(raiz registry.Key, caminho string) []string {
	k, err := registry.OpenKey(raiz, caminho, registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()
	nomes, _ := k.ReadValueNames(-1)
	return nomes
}

func subchaves(raiz registry.Key, caminho string) []string {
	k, err := registry.OpenKey(raiz, caminho, registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()
	nomes, _ := k.ReadSubKeyNames(-1)
	return nomes
}

type valorRegistro struct {
	Nome  string
	Texto string
	Bytes []byte
	Tipo  uint32
}

func valoresDaChave(raiz registry.Key, caminho string) []valorRegistro {
	k, err := registry.OpenKey(raiz, caminho, registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()
	nomes, _ := k.ReadValueNames(-1)
	var lista []valorRegistro
	for _, n := range nomes {
		v := valorRegistro{Nome: n}
		buf := make([]byte, 4096)
		tam, tipo, err := k.GetValue(n, buf)
		if err != nil && tam > len(buf) {
			buf = make([]byte, tam)
			tam, tipo, err = k.GetValue(n, buf)
		}
		if err != nil {
			continue
		}
		v.Tipo = tipo
		v.Bytes = buf[:tam]
		switch tipo {
		case registry.SZ, registry.EXPAND_SZ:
			v.Texto = utf16DeBytes(v.Bytes)
		case registry.DWORD:
			if tam >= 4 {
				v.Texto = fmt.Sprint(binary.LittleEndian.Uint32(v.Bytes))
			}
		}
		lista = append(lista, v)
	}
	return lista
}

func perfisDeUsuario() []Perfil {
	const lista = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
	carregados := map[string]bool{}
	for _, s := range subchaves(registry.USERS, "") {
		carregados[strings.ToUpper(s)] = true
	}
	var perfis []Perfil
	for _, sid := range subchaves(registry.LOCAL_MACHINE, lista) {
		if !strings.HasPrefix(sid, "S-1-5-21-") {
			continue
		}
		pasta, ok := lerString(registry.LOCAL_MACHINE, lista+`\`+sid, "ProfileImagePath")
		if !ok {
			continue
		}
		perfis = append(perfis, Perfil{SID: sid, Pasta: pasta, Usuario: filepath.Base(pasta), Hive: carregados[strings.ToUpper(sid)]})
	}
	return perfis
}

func dataInstalacaoWindows() time.Time {
	if v, ok := lerDword(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "InstallDate"); ok && v > 0 {
		return time.Unix(int64(v), 0)
	}
	return time.Time{}
}

func versaoWindows() string {
	const chave = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	produto, _ := lerString(registry.LOCAL_MACHINE, chave, "ProductName")
	build, _ := lerString(registry.LOCAL_MACHINE, chave, "CurrentBuild")
	ubr, _ := lerDword(registry.LOCAL_MACHINE, chave, "UBR")
	versao, _ := lerString(registry.LOCAL_MACHINE, chave, "DisplayVersion")
	return fmt.Sprintf("%s %s (build %s.%d)", produto, versao, build, ubr)
}

var (
	versionDLL                   = windows.NewLazySystemDLL("version.dll")
	user32                       = windows.NewLazySystemDLL("user32.dll")
	procGetFileVersionInfoSizeW  = versionDLL.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW      = versionDLL.NewProc("GetFileVersionInfoW")
	procVerQueryValueW           = versionDLL.NewProc("VerQueryValueW")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procGetWindowTextW           = user32.NewProc("GetWindowTextW")
	procGetClassNameW            = user32.NewProc("GetClassNameW")
	procGetWindowLongPtrW        = user32.NewProc("GetWindowLongPtrW")
	procGetWindowRect            = user32.NewProc("GetWindowRect")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procGetSystemMetrics         = user32.NewProc("GetSystemMetrics")
	procEnumProcesses            = psapi.NewProc("EnumProcesses")
)

func consultaVersao(bloco []byte, sub string) string {
	p, _ := syscall.UTF16PtrFromString(sub)
	var ptr *uint16
	var tam uint32
	ok, _, _ := procVerQueryValueW.Call(uintptr(unsafe.Pointer(&bloco[0])), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&tam)))
	if ok == 0 || ptr == nil || tam == 0 {
		return ""
	}
	return windows.UTF16PtrToString(ptr)
}

func infoDeVersao(caminho string) (original, produto, empresa, descricao string) {
	p, err := syscall.UTF16PtrFromString(caminho)
	if err != nil {
		return
	}
	var manip uint32
	tam, _, _ := procGetFileVersionInfoSizeW.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&manip)))
	if tam == 0 {
		return
	}
	bloco := make([]byte, tam)
	if ok, _, _ := procGetFileVersionInfoW.Call(uintptr(unsafe.Pointer(p)), 0, tam, uintptr(unsafe.Pointer(&bloco[0]))); ok == 0 {
		return
	}
	traducoes := []string{"040904B0", "040904E4", "041604B0", "000004B0"}
	trad, _ := syscall.UTF16PtrFromString(`\VarFileInfo\Translation`)
	var par *[2]uint16
	var tamTrad uint32
	if ok, _, _ := procVerQueryValueW.Call(uintptr(unsafe.Pointer(&bloco[0])), uintptr(unsafe.Pointer(trad)), uintptr(unsafe.Pointer(&par)), uintptr(unsafe.Pointer(&tamTrad))); ok != 0 && par != nil && tamTrad >= 4 {
		traducoes = append([]string{fmt.Sprintf("%04X%04X", par[0], par[1])}, traducoes...)
	}
	for _, t := range traducoes {
		original = consultaVersao(bloco, `\StringFileInfo\`+t+`\OriginalFilename`)
		produto = consultaVersao(bloco, `\StringFileInfo\`+t+`\ProductName`)
		empresa = consultaVersao(bloco, `\StringFileInfo\`+t+`\CompanyName`)
		descricao = consultaVersao(bloco, `\StringFileInfo\`+t+`\FileDescription`)
		if original != "" || produto != "" || descricao != "" {
			return
		}
	}
	return
}

func horaDeCriacao(pid uint32) time.Time {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return time.Time{}
	}
	defer windows.CloseHandle(h)
	var criacao, saida, kernel, usuario windows.Filetime
	if err := windows.GetProcessTimes(h, &criacao, &saida, &kernel, &usuario); err != nil {
		return time.Time{}
	}
	return time.Unix(0, criacao.Nanoseconds()).Local()
}

type entradaHandle struct {
	Object                uintptr
	UniqueProcessId       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

func tabelaDeHandles() ([]entradaHandle, error) {
	tam := uint32(4 * 1024 * 1024)
	for tentativa := 0; tentativa < 8; tentativa++ {
		buf := make([]byte, tam)
		var ret uint32
		err := windows.NtQuerySystemInformation(64, unsafe.Pointer(&buf[0]), tam, &ret)
		if err == nil {
			total := int(*(*uintptr)(unsafe.Pointer(&buf[0])))
			tamEntrada := int(unsafe.Sizeof(entradaHandle{}))
			if 16+total*tamEntrada > len(buf) {
				total = (len(buf) - 16) / tamEntrada
			}
			if total <= 0 {
				return nil, nil
			}
			vista := unsafe.Slice((*entradaHandle)(unsafe.Pointer(&buf[16])), total)
			entradas := make([]entradaHandle, total)
			copy(entradas, vista)
			return entradas, nil
		}
		if err == windows.STATUS_INFO_LENGTH_MISMATCH || ret > tam {
			if ret > tam {
				tam = ret + 1024*1024
			} else {
				tam *= 2
			}
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("tabela de handles grande demais")
}

func handlesAbertosNoProcesso(alvo uint32) ([]HandleNoFiveM, error) {
	eu := windows.GetCurrentProcessId()
	meu, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, eu)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(meu)

	entradas, err := tabelaDeHandles()
	if err != nil {
		return nil, err
	}
	tipoProcesso := uint16(0)
	for _, e := range entradas {
		if uint32(e.UniqueProcessId) == eu && e.HandleValue == uintptr(meu) {
			tipoProcesso = e.ObjectTypeIndex
			break
		}
	}
	if tipoProcesso == 0 {
		for _, e := range entradas {
			if uint32(e.UniqueProcessId) == eu {
				var dup windows.Handle
				if windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(e.HandleValue), windows.CurrentProcess(), &dup, windows.PROCESS_QUERY_LIMITED_INFORMATION, false, 0) != nil {
					continue
				}
				pid, errPid := windows.GetProcessId(dup)
				windows.CloseHandle(dup)
				if errPid == nil && pid > 0 {
					tipoProcesso = e.ObjectTypeIndex
					break
				}
			}
		}
	}
	if tipoProcesso == 0 {
		return nil, fmt.Errorf("nao identifiquei o tipo de objeto processo na tabela do kernel")
	}
	fontes := map[uint32]windows.Handle{}
	defer func() {
		for _, h := range fontes {
			windows.CloseHandle(h)
		}
	}()
	var achados []HandleNoFiveM
	for _, e := range entradas {
		dono := uint32(e.UniqueProcessId)
		if e.ObjectTypeIndex != tipoProcesso || dono == eu || dono == alvo || dono <= 4 {
			continue
		}
		src, ok := fontes[dono]
		if !ok {
			h, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, dono)
			if err != nil {
				fontes[dono] = 0
				continue
			}
			fontes[dono] = h
			src = h
		}
		if src == 0 {
			continue
		}
		var dup windows.Handle
		if err := windows.DuplicateHandle(src, windows.Handle(e.HandleValue), windows.CurrentProcess(), &dup, windows.PROCESS_QUERY_LIMITED_INFORMATION, false, 0); err != nil {
			continue
		}
		pidDoObjeto, err := windows.GetProcessId(dup)
		windows.CloseHandle(dup)
		if err == nil && pidDoObjeto == alvo {
			achados = append(achados, HandleNoFiveM{DonoPID: int(dono), Acesso: e.GrantedAccess})
		}
	}
	return achados, nil
}

type retangulo struct{ Esq, Topo, Dir, Base int32 }

func janelasAbertas() []JanelaVista {
	var lista []JanelaVista
	cb := windows.NewCallback(func(hwnd uintptr, lparam uintptr) uintptr {
		var pid uint32
		procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		titulo := make([]uint16, 512)
		n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&titulo[0])), uintptr(len(titulo)))
		classe := make([]uint16, 256)
		m, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&classe[0])), uintptr(len(classe)))
		estilo, _, _ := procGetWindowLongPtrW.Call(hwnd, ^uintptr(19))
		var r retangulo
		procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
		visivel, _, _ := procIsWindowVisible.Call(hwnd)
		lista = append(lista, JanelaVista{
			PID: int(pid), Titulo: windows.UTF16ToString(titulo[:n]), Classe: windows.UTF16ToString(classe[:m]),
			Largura: int(r.Dir - r.Esq), Altura: int(r.Base - r.Topo),
			Layered: estilo&0x80000 != 0, Transparente: estilo&0x20 != 0, Topmost: estilo&0x8 != 0, Visivel: visivel != 0,
		})
		return 1
	})
	procEnumWindows.Call(cb, 0)
	return lista
}

func tamanhoDaTela() (int, int) {
	w, _, _ := procGetSystemMetrics.Call(0)
	h, _, _ := procGetSystemMetrics.Call(1)
	return int(w), int(h)
}

func pidsViaEnumProcesses() map[uint32]bool {
	buf := make([]uint32, 4096)
	var ret uint32
	ok, _, _ := procEnumProcesses.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*4), uintptr(unsafe.Pointer(&ret)))
	saida := map[uint32]bool{}
	if ok == 0 {
		return saida
	}
	for _, pid := range buf[:ret/4] {
		saida[pid] = true
	}
	return saida
}

func pidsViaNtQuery() map[uint32]bool {
	saida := map[uint32]bool{}
	tam := uint32(2 * 1024 * 1024)
	for tentativa := 0; tentativa < 6; tentativa++ {
		buf := make([]byte, tam)
		var ret uint32
		err := windows.NtQuerySystemInformation(5, unsafe.Pointer(&buf[0]), tam, &ret)
		if err != nil {
			if ret > tam {
				tam = ret + 512*1024
			} else {
				tam *= 2
			}
			continue
		}
		off := 0
		for {
			if off+96 > len(buf) {
				break
			}
			prox := binary.LittleEndian.Uint32(buf[off:])
			pid := binary.LittleEndian.Uint64(buf[off+80:])
			saida[uint32(pid)] = true
			if prox == 0 {
				break
			}
			off += int(prox)
		}
		return saida
	}
	return saida
}

func assinaturasAuthenticode(caminhos []string) map[string][2]string {
	saida := map[string][2]string{}
	if len(caminhos) == 0 {
		return saida
	}
	var partes []string
	for _, c := range caminhos {
		partes = append(partes, "'"+strings.ReplaceAll(c, "'", "''")+"'")
	}
	script := "Get-AuthenticodeSignature -LiteralPath @(" + strings.Join(partes, ",") + ") | Select-Object Path,@{n='Status';e={$_.Status.ToString()}},@{n='Signer';e={if($_.SignerCertificate){$_.SignerCertificate.Subject}else{''}}} | ConvertTo-Json -Compress"
	texto, err := powershell(script)
	if err != nil {
		return saida
	}
	var bruto any
	if json.Unmarshal([]byte(strings.TrimSpace(texto)), &bruto) != nil {
		return saida
	}
	for _, item := range objetosDeQualquer(bruto) {
		caminho, _ := item["Path"].(string)
		status, _ := item["Status"].(string)
		signer, _ := item["Signer"].(string)
		saida[strings.ToLower(caminho)] = [2]string{status, signer}
	}
	return saida
}

type infoRegiao struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

const (
	memCommit  = 0x1000
	memPrivate = 0x20000
	memImage   = 0x1000000
	memMapped  = 0x40000

	pageExecute          = 0x10
	pageExecuteRead      = 0x20
	pageExecuteReadWrite = 0x40
	pageExecuteWriteCopy = 0x80
	pageGuard            = 0x100
)

func protecaoExecutavel(p uint32) bool {
	base := p &^ uint32(pageGuard|0x200|0x400)
	return base == pageExecute || base == pageExecuteRead || base == pageExecuteReadWrite || base == pageExecuteWriteCopy
}

func nomeProtecao(p uint32) string {
	switch p &^ uint32(pageGuard|0x200|0x400) {
	case pageExecute:
		return "X"
	case pageExecuteRead:
		return "RX"
	case pageExecuteReadWrite:
		return "RWX"
	case pageExecuteWriteCopy:
		return "WCX"
	}
	return fmt.Sprintf("0x%X", p)
}

func nomeTipoRegiao(t uint32) string {
	switch t {
	case memImage:
		return "imagem (dll/exe registrado)"
	case memMapped:
		return "arquivo mapeado"
	case memPrivate:
		return "privada (sem arquivo)"
	}
	return fmt.Sprintf("0x%X", t)
}

func protecaoLegivel(p uint32) bool {
	if p&pageGuard != 0 {
		return false
	}
	base := p &^ uint32(pageGuard|0x200|0x400)
	return base != 0 && base != 0x01
}

func varrerMemoriaLegivel(pid uint32, limiteBytes int64, fn func(RegiaoDeMemoria, []byte)) (int64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)

	const pedaco = 8 * 1024 * 1024
	buf := make([]byte, pedaco)
	var endereco uintptr
	var lidos int64
	for limiteBytes <= 0 || lidos < limiteBytes {
		var info infoRegiao
		if err := windows.VirtualQueryEx(h, endereco, (*windows.MemoryBasicInformation)(unsafe.Pointer(&info)), unsafe.Sizeof(info)); err != nil || info.RegionSize == 0 {
			break
		}
		proximo := info.BaseAddress + info.RegionSize
		if proximo <= endereco {
			break
		}
		if info.State == memCommit && info.Type == memPrivate && protecaoLegivel(info.Protect) {
			for desloc := uintptr(0); desloc < info.RegionSize; desloc += pedaco {
				tamanho := info.RegionSize - desloc
				if tamanho > pedaco {
					tamanho = pedaco
				}
				var lidosAqui uintptr
				if err := windows.ReadProcessMemory(h, info.BaseAddress+desloc, &buf[0], tamanho, &lidosAqui); err != nil || lidosAqui == 0 {
					break
				}
				lidos += int64(lidosAqui)
				fn(RegiaoDeMemoria{Base: uint64(info.BaseAddress + desloc), Tamanho: uint64(lidosAqui), Protecao: nomeProtecao(info.Protect), Tipo: nomeTipoRegiao(info.Type), Privada: true}, buf[:lidosAqui])
				if limiteBytes > 0 && lidos >= limiteBytes {
					break
				}
			}
		}
		endereco = proximo
	}
	return lidos, nil
}

func varrerMemoriaExecutavel(pid uint32, limiteBytes int64, fn func(RegiaoDeMemoria, []byte)) error {
	_, err := varrerMemoriaExecutavelContando(pid, limiteBytes, fn)
	return err
}

func varrerMemoriaExecutavelContando(pid uint32, limiteBytes int64, fn func(RegiaoDeMemoria, []byte)) (int, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)

	falhas := 0
	var endereco uintptr
	var lidos int64
	for lidos < limiteBytes {
		var info infoRegiao
		if err := windows.VirtualQueryEx(h, endereco, (*windows.MemoryBasicInformation)(unsafe.Pointer(&info)), unsafe.Sizeof(info)); err != nil || info.RegionSize == 0 {
			break
		}
		proximo := info.BaseAddress + info.RegionSize
		if proximo <= endereco {
			break
		}
		if info.State == memCommit && protecaoExecutavel(info.Protect) && info.Type != memImage {
			tamanho := int64(info.RegionSize)
			if tamanho > 16*1024*1024 {
				tamanho = 16 * 1024 * 1024
			}
			buf := make([]byte, tamanho)
			var lidosAqui uintptr
			if err := windows.ReadProcessMemory(h, info.BaseAddress, &buf[0], uintptr(tamanho), &lidosAqui); err != nil || lidosAqui == 0 {
				falhas++
			} else {
				lidos += int64(lidosAqui)
				fn(RegiaoDeMemoria{
					Base:       uint64(info.BaseAddress),
					Tamanho:    uint64(info.RegionSize),
					Protecao:   nomeProtecao(info.Protect),
					Tipo:       nomeTipoRegiao(info.Type),
					Privada:    info.Type == memPrivate,
					Executavel: true,
				}, buf[:lidosAqui])
			}
		}
		endereco = proximo
	}
	return falhas, nil
}

func executarStream(limite time.Duration, fn func(io.Reader) error, nome string, args ...string) error {
	return executarStreamCancelavel(limite, nil, fn, nome, args...)
}

func executarStreamCancelavel(limite time.Duration, cancelar func() bool, fn func(io.Reader) error, nome string, args ...string) error {
	cmd := exec.Command(nome, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	saida, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	pronto := make(chan error, 1)
	go func() { pronto <- fn(saida) }()
	var prazo <-chan time.Time
	if limite > 0 {
		prazo = time.After(limite)
	}
	pulso := time.NewTicker(500 * time.Millisecond)
	defer pulso.Stop()
	var erroLeitura error
	esperando := true
	for esperando {
		select {
		case erroLeitura = <-pronto:
			esperando = false
		case <-prazo:
			erroLeitura = errTempoEsgotado
			esperando = false
		case <-pulso.C:
			if cancelar != nil && cancelar() {
				erroLeitura = errCancelado
				esperando = false
			}
		}
	}
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
	io.Copy(io.Discard, saida)
	cmd.Wait()
	return erroLeitura
}

type dadosDeStream struct {
	StreamSize int64
	StreamName [296]uint16
}

var (
	procFindFirstStreamW = kernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = kernel32.NewProc("FindNextStreamW")
)

func streamsAlternativos(caminho string) []StreamOculto {
	p, err := syscall.UTF16PtrFromString(caminho)
	if err != nil {
		return nil
	}
	var dados dadosDeStream
	h, _, _ := procFindFirstStreamW.Call(uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&dados)), 0)
	if h == 0 || h == uintptr(windows.InvalidHandle) {
		return nil
	}
	defer windows.FindClose(windows.Handle(h))
	var lista []StreamOculto
	for i := 0; i < 64; i++ {
		nome := windows.UTF16ToString(dados.StreamName[:])
		if nome != "::$DATA" && nome != "" {
			lista = append(lista, StreamOculto{Arquivo: caminho, Stream: nome, Tamanho: dados.StreamSize})
		}
		ok, _, _ := procFindNextStreamW.Call(h, uintptr(unsafe.Pointer(&dados)))
		if ok == 0 {
			break
		}
	}
	return lista
}

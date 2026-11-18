package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

const privSeedHex = "a4b98891bae5401ddb80641d3b4b6771672f5b8568619eef683c075514633afa"

var (
	b32   = base32.StdEncoding.WithPadding(base32.NoPadding)
	epoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
)

type record struct {
	Time    string `json:"time"`
	Machine string `json:"machine"`
	Note    string `json:"note"`
	Expires string `json:"expires"`
	Code    string `json:"code"`
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func clean(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func group(s string, n int) string {
	var parts []string
	for len(s) > n {
		parts = append(parts, s[:n])
		s = s[n:]
	}
	if s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, "-")
}

func makeCode(machine string, days uint16) (string, error) {
	m := clean(machine)
	if len(m) != 16 {
		return "", fmt.Errorf("机器码应该是 16 位字母数字（形如 ABCD-EFGH-IJKL-MNOP），请让对方重新复制")
	}
	seed, err := hex.DecodeString(privSeedHex)
	if err != nil {
		return "", err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	msg := []byte(fmt.Sprintf("YDM1|%s|%d", m, days))
	sig := ed25519.Sign(priv, msg)
	raw := make([]byte, 2+len(sig))
	binary.BigEndian.PutUint16(raw[:2], days)
	copy(raw[2:], sig)
	return group(b32.EncodeToString(raw), 6), nil
}

func recPath() string {
	return filepath.Join(exeDir(), "授权记录.json")
}

func loadRecs() []record {
	data, err := os.ReadFile(recPath())
	if err != nil {
		return nil
	}
	var recs []record
	_ = json.Unmarshal(data, &recs)
	return recs
}

func openWindow(url string) {
	profileDir := filepath.Join(exeDir(), ".ui-keygen")
	args := []string{
		"--app=" + url,
		"--window-size=760,720",
		"--user-data-dir=" + profileDir,
		"--no-first-run",
		"--disable-features=Translate",
	}
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("LocalAppData"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("LocalAppData"), `Google\Chrome\Application\chrome.exe`),
	}
	for _, bin := range candidates {
		if _, err := os.Stat(bin); err == nil {
			if exec.Command(bin, args...).Start() == nil {
				return
			}
		}
	}
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func main() {
	var tokBytes [16]byte
	_, _ = rand.Read(tokBytes[:])
	token := hex.EncodeToString(tokBytes[:])

	var (
		mu       sync.Mutex
		lastSeen = time.Now()
	)

	guard := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Token") != token {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			mu.Lock()
			lastSeen = time.Now()
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			fn(w, r)
		}
	}

	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	mux.HandleFunc("/api/ping", guard(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	}))

	mux.HandleFunc("/api/list", guard(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"records": loadRecs(),
		})
	}))

	mux.HandleFunc("/api/make", guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Machine string
			Note    string
			Expires string
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		var days uint16
		if req.Expires != "" {
			exp, err := time.Parse("2006-01-02", req.Expires)
			if err != nil {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok":  false,
					"err": "到期日期不对，请选一个今天之后的日期",
				})
				return
			}
			d := int(exp.Sub(epoch).Hours() / 24)
			if d < 1 || d > 65000 || exp.Before(time.Now().AddDate(0, 0, -1)) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok":  false,
					"err": "到期日期不对，请选一个今天之后的日期",
				})
				return
			}
			days = uint16(d)
		}

		code, err := makeCode(req.Machine, days)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":  false,
				"err": err.Error(),
			})
			return
		}

		mu.Lock()
		rec := record{
			Time:    time.Now().Format("2006-01-02 15:04"),
			Machine: group(clean(req.Machine), 4),
			Note:    strings.TrimSpace(req.Note),
			Expires: req.Expires,
			Code:    code,
		}
		recs := append([]record{rec}, loadRecs()...)
		if data, err := json.MarshalIndent(recs, "", "  "); err == nil {
			_ = os.WriteFile(recPath(), data, 0600)
		}
		mu.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"code":    code,
			"records": recs,
		})
	}))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	url := fmt.Sprintf("http://%s/#t=%s", ln.Addr().String(), token)
	go func() {
		_ = (&http.Server{Handler: mux}).Serve(ln)
	}()

	openWindow(url)
	for {
		time.Sleep(3 * time.Second)
		mu.Lock()
		idle := time.Since(lastSeen)
		mu.Unlock()
		if idle > 15*time.Second {
			os.Exit(0)
		}
	}
}

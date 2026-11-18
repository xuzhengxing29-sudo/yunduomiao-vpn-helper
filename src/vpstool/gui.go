package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

type Job struct {
	mu       sync.Mutex
	Kind     string    `json:"kind"`
	Steps    []string  `json:"steps"`
	Step     int       `json:"step"`
	Lines    []string  `json:"lines"`
	Done     bool      `json:"done"`
	Err      string    `json:"err"`
	Files    []string  `json:"files"`
	OutDir   string    `json:"outDir"`
	PanelURL string    `json:"panelUrl"`
	Report   []Finding `json:"report"`
}

func (j *Job) log(msg string) {
	j.mu.Lock()
	j.Lines = append(j.Lines, msg)
	j.mu.Unlock()
}

func (j *Job) setStep(step int) {
	j.mu.Lock()
	j.Step = step
	j.mu.Unlock()
}

func (j *Job) snapshot() map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	b, _ := json.Marshal(j)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

type App struct {
	mu           sync.Mutex
	token        string
	lastSeen     time.Time
	sess         *session
	panel        *Panel
	job          *Job
	healths      map[string]ExitHealth
	healthCheck  bool
	cachedOps    []apiOp
	noToolModels map[string]bool
}

func (a *App) running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.job == nil {
		return false
	}
	a.job.mu.Lock()
	defer a.job.mu.Unlock()
	return !a.job.Done
}

func (a *App) startJob(kind string, steps []string, fn func(j *Job) error) error {
	a.mu.Lock()
	if a.job != nil {
		a.job.mu.Lock()
		busy := !a.job.Done
		a.job.mu.Unlock()
		if busy {
			a.mu.Unlock()
			return errors.New("上一个任务还在进行中")
		}
	}
	j := &Job{
		Kind:   kind,
		Steps:  steps,
		Lines:  []string{},
		Files:  []string{},
		Report: []Finding{},
	}
	a.job = j
	a.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				j.mu.Lock()
				j.Err = "程序出错：" + fmt.Sprint(r)
				j.Done = true
				j.mu.Unlock()
			}
		}()
		err := fn(j)
		j.mu.Lock()
		if err != nil {
			j.Err = err.Error()
		} else if len(j.Steps) > 0 {
			j.Step = len(j.Steps)
		}
		j.Done = true
		j.mu.Unlock()
	}()
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	msg := "出错了"
	if err != nil {
		msg = err.Error()
	}
	writeJSON(w, map[string]any{
		"ok":  false,
		"err": msg,
	})
}

func decode(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

func (a *App) guard(path string, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != a.token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		a.mu.Lock()
		a.lastSeen = time.Now()
		a.mu.Unlock()

		if path != "/api/ping" && !strings.HasPrefix(path, "/api/license") {
			if ok, _, reason := loadLicense(); !ok {
				if reason == "" {
					reason = "这台电脑还没有激活"
				}
				writeJSON(w, map[string]any{
					"ok":         false,
					"err":        reason,
					"unlicensed": true,
				})
				return
			}
		}
		fn(w, r)
	}
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	reg := func(p string, fn http.HandlerFunc) {
		mux.HandleFunc(p, a.guard(p, fn))
	}

	reg("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"ok": true})
	})
	reg("/api/connect", a.apiConnect)
	reg("/api/probe", a.apiProbe)
	reg("/api/deploy", a.apiDeploy)
	reg("/api/job", a.apiJob)
	reg("/api/exits", a.apiExits)
	reg("/api/exits/add", a.apiAddExits)
	reg("/api/exits/delete", a.apiDelExit)
	reg("/api/exits/adopt", a.apiAdoptExit)
	reg("/api/exits/health", a.apiExitHealth)
	reg("/api/exits/repair", a.apiExitRepair)
	reg("/api/export", a.apiExport)
	reg("/api/checkup", a.apiCheckup)
	reg("/api/open", a.apiOpen)
	reg("/api/recent", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"ok":      true,
			"servers": publicRecent(),
			"version": version,
		})
	})
	reg("/api/recent/forget", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP           string `json:"ip"`
			User         string `json:"user"`
			PasswordOnly bool   `json:"passwordOnly"`
		}
		_ = decode(r, &req)
		if req.PasswordOnly {
			forgetSecret(req.IP, req.User)
		} else {
			forgetRecent(req.IP, req.User)
		}
		writeJSON(w, map[string]any{
			"ok":      true,
			"servers": publicRecent(),
		})
	})
	reg("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if a.running() {
			fail(w, errors.New("任务进行中，不能断开"))
			return
		}
		a.mu.Lock()
		if a.sess != nil {
			a.sess.close()
			a.sess = nil
		}
		a.panel = nil
		a.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true})
	})
	reg("/api/license", func(w http.ResponseWriter, r *http.Request) {
		ok, exp, reason := loadLicense()
		writeJSON(w, map[string]any{
			"ok":       true,
			"licensed": ok,
			"machine":  machineCode(),
			"expires":  exp,
			"reason":   reason,
			"version":  version,
		})
	})
	reg("/api/license/activate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
		}
		_ = decode(r, &req)
		exp, err := activate(req.Code)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]any{
			"ok":      true,
			"expires": exp,
		})
	})
	reg("/api/line/update", a.apiLineUpdate)
	reg("/api/line/reset", a.apiLineReset)
	reg("/api/status", a.apiStatus)
	reg("/api/backup", a.apiBackup)
	reg("/api/exec", a.apiExec)
	reg("/api/passwd", a.apiPasswd)
	reg("/api/security", a.apiSecurity)
	reg("/api/ai/config", a.apiAIConfig)
	reg("/api/ai/save", a.apiAISave)
	reg("/api/ai/chat", a.apiAIChat)
	reg("/api/ai/check", a.apiAICheck)
	reg("/api/panel/open", a.apiPanelOpen)
	reg("/api/ai/paneldocs", a.apiPanelDocs)
	reg("/api/ai/panelcall", a.apiPanelCall)
	reg("/api/ai/kb", a.apiKBSearch)
	reg("/api/ai/kbinfo", a.apiKBInfo)
	reg("/api/ai/kbopen", a.apiKBOpen)
	reg("/api/ai/note", a.apiNoteAdd)
	reg("/api/ai/noteclear", a.apiNoteClear)
	reg("/api/doctor", a.apiDoctor)
	reg("/api/doctor/fix", a.apiDoctorFix)
	reg("/api/quickcheck", a.apiQuickCheck)
	return mux
}

type connectReq struct {
	IP       string `json:"ip"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	KeyPEM   string `json:"keyPEM"`
	KeyPass  string `json:"keyPass"`
	Remember bool   `json:"remember"`
	Saved    bool   `json:"saved"`
}

func (a *App) apiConnect(w http.ResponseWriter, r *http.Request) {
	if a.running() {
		fail(w, errors.New("上一个任务还在进行中"))
		return
	}
	var req connectReq
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	req.Port = strings.TrimSpace(req.Port)
	req.User = strings.TrimSpace(req.User)
	if req.IP == "" {
		fail(w, errors.New("请填写 VPS 的 IP 地址"))
		return
	}

	usedSaved := false
	if req.Saved && req.Password == "" && req.KeyPEM == "" {
		for _, rec := range loadRecent() {
			if rec.IP == req.IP && (req.User == "" || rec.User == req.User) {
				if req.Port == "" {
					req.Port = rec.Port
				}
				if req.User == "" {
					req.User = rec.User
				}
				if sec := rec.secret(); sec != nil {
					req.Password = sec.Password
					req.KeyPEM = sec.KeyPEM
					req.KeyPass = sec.KeyPass
					usedSaved = true
				}
				break
			}
		}
	}
	if req.Port == "" {
		req.Port = "22"
	}
	if req.User == "" {
		req.User = "root"
	}
	if req.Password == "" && req.KeyPEM == "" {
		if req.Saved {
			fail(w, errors.New("这台服务器没有记住密码（或者记住的密码在这台电脑上解不开了），请重新输入一次"))
			return
		}
		fail(w, errors.New("请填写 SSH 密码或选择私钥文件"))
		return
	}

	a.mu.Lock()
	if a.sess != nil {
		a.sess.close()
		a.sess = nil
	}
	a.panel = nil
	a.cachedOps = nil
	a.healths = nil
	a.healthCheck = false
	a.mu.Unlock()

	outDir := filepath.Join(exeDir(), "输出", sanitize(req.IP))
	_ = os.MkdirAll(outDir, 0755)
	logFile, _ := os.OpenFile(filepath.Join(outDir, "运行日志.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if logFile != nil {
		fmt.Fprintf(logFile, "\n===== %s =====\n", time.Now().Format("2006-01-02 15:04:05"))
	}
	rw := &redactWriter{w: logFile, secrets: []string{req.Password, req.KeyPass}}

	var tmpKey string
	if req.KeyPEM != "" {
		tmpKey = filepath.Join(outDir, ".tmp_key")
		_ = os.WriteFile(tmpKey, []byte(req.KeyPEM), 0600)
		defer os.Remove(tmpKey)
	}

	rem, err := Dial(req.IP, req.Port, req.User, req.Password, tmpKey, req.KeyPass, func(fp string) bool {
		return true
	}, rw)
	if err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		if usedSaved {
			fail(w, fmt.Errorf("%v\n（用的是上次记住的密码。如果你改过密码，请在下面重新输入一次）", err))
			return
		}
		fail(w, err)
		return
	}

	info, err := Preflight(rem, req.IP)
	if err != nil {
		_ = rem.Client.Close()
		if logFile != nil {
			_ = logFile.Close()
		}
		fail(w, err)
		return
	}

	sess := &session{remote: rem, info: info, outDir: outDir, logFile: logFile}
	a.mu.Lock()
	a.sess = sess
	a.mu.Unlock()

	rec := recentServer{
		IP:   req.IP,
		Port: req.Port,
		User: req.User,
		OS:   info.OSID + " " + info.OSVer,
		Time: time.Now().Unix(),
	}
	if req.Remember || usedSaved {
		rec.setSecret(&savedLogin{
			Password: req.Password,
			KeyPEM:   req.KeyPEM,
			KeyPass:  req.KeyPass,
		})
	}
	saveRecent(rec, req.Remember || usedSaved)

	writeJSON(w, map[string]any{
		"ok":          true,
		"ip":          info.IP,
		"os":          info.OSID + " " + info.OSVer,
		"xui":         info.HasXUI,
		"fingerprint": rem.Fingerprint,
		"outDir":      outDir,
	})
}

func (a *App) session() (*session, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil || a.sess.remote == nil {
		return nil, errors.New("还没有连接服务器")
	}
	return a.sess, nil
}

func (a *App) loadPanel() (*Panel, error) {
	sess, err := a.session()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.panel != nil {
		p := a.panel
		a.mu.Unlock()
		return p, nil
	}
	a.mu.Unlock()

	p, err := LoadPanel(sess.remote, sess.info.IP)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.panel = p
	a.mu.Unlock()
	return p, nil
}

func (a *App) apiProbe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Line string `json:"line"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	rp, err := ParseProxyLine(req.Line)
	if err != nil {
		fail(w, err)
		return
	}
	pr := ProbeExit(sess.remote, rp)
	countryNames := map[string]string{
		"CN": "中国", "US": "美国", "JP": "日本", "HK": "香港",
		"SG": "新加坡", "TW": "台湾", "KR": "韩国", "GB": "英国", "DE": "德国",
	}
	cc := strings.ToUpper(pr.Country)
	label := strings.TrimSpace(countryNames[cc] + "-" + pr.City)
	label = strings.Trim(label, "-")
	writeJSON(w, map[string]any{
		"ok":        true,
		"reachable": pr.Reachable,
		"text":      pr.String(),
		"ip":        pr.IP,
		"country":   cc,
		"city":      pr.City,
		"org":       pr.Org,
		"hosting":   pr.Hosting,
		"label":     label,
		"flag":      strings.TrimSpace(flagFor(cc)),
	})
}

type exitReq struct {
	Line   string `json:"line"`
	Label  string `json:"label"`
	Region string `json:"region"`
}

func isCNRegion(region string) bool {
	r := strings.TrimSpace(strings.ToUpper(region))
	return r == "CN" || r == "CHINA" || region == "中国" || region == "国内"
}

func toSpecs(items []exitReq, existing []PClient, xray map[string]any) ([]ExitSpec, error) {
	fake := append([]PClient{}, existing...)
	var specs []ExitSpec
	for _, item := range items {
		rp, err := ParseProxyLine(item.Line)
		if err != nil {
			return nil, fmt.Errorf("「%s」：%v", item.Label, err)
		}
		email := NextExitName(fake, xray)
		label := strings.TrimSpace(item.Label)
		if label == "" {
			label = email
		}
		specs = append(specs, ExitSpec{
			Email: email,
			Label: label,
			China: isCNRegion(item.Region),
			Proxy: rp,
		})
		fake = append(fake, PClient{Email: email})
	}
	return specs, nil
}

func (a *App) apiDeploy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode  string    `json:"mode"`
		SNI   string    `json:"sni"`
		Exits []exitReq `json:"exits"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	if req.SNI == "" {
		req.SNI = "www.icloud.com"
	}
	steps := []string{
		"安装基础组件、开启网络加速",
		"安装 3x-ui 面板",
		"创建三条入口线路",
		"配置路由规则",
		"创建出口",
		"重启并检查端口",
		"防暴力破解、自动更新",
		"开启防火墙",
		"生成配置文件",
	}
	err = a.startJob("deploy", steps, func(j *Job) error {
		j.setStep(0)
		skipped, err := InstallBase(sess.remote)
		if err != nil {
			return fmt.Errorf("安装基础组件失败：%v", err)
		}
		if skipped {
			j.log("· 基础组件和网络加速以前已经装好，跳过")
		}

		j.setStep(1)
		if sess.info.HasXUI {
			j.log("· 已经装过 3x-ui，保留现有面板")
		} else {
			j.log("正在下载并安装 3x-ui（需要几分钟）...")
			if err := InstallXUI(sess.remote, sess.info.IP); err != nil {
				return fmt.Errorf("安装 3x-ui 失败：%v", err)
			}
			sess.info.HasXUI = true
		}

		p, err := LoadPanel(sess.remote, sess.info.IP)
		if err != nil {
			return fmt.Errorf("面板接口无法访问，请检查 3x-ui 是否在运行（%v）", err)
		}
		a.mu.Lock()
		a.panel = p
		a.mu.Unlock()
		_, _ = p.XrayState()
		writePanelInfo(sess.outDir, p, sess.info)
		j.mu.Lock()
		j.PanelURL = p.PublicURL
		j.OutDir = sess.outDir
		j.mu.Unlock()
		j.log("✓ 面板地址和账号已保存到「面板信息.txt」")

		j.setStep(2)
		if err := MakeHy2Cert(sess.remote); err != nil {
			return err
		}
		inboundIDs, err := EnsureInbounds(p, req.SNI, j.log)
		if err != nil {
			return err
		}

		j.setStep(3)
		xray, testURL, err := p.GetXray()
		if err != nil {
			return err
		}
		EnsureBaseRules(xray, req.Mode == "1" || req.Mode == "fanqiang")
		if err := p.SaveXray(xray, testURL); err != nil {
			return err
		}
		j.log("✓ 路由规则已配置")

		j.setStep(4)
		clients, _ := p.Clients()
		hasDirect := false
		for _, c := range clients {
			if c.Email == "VPS" {
				hasDirect = true
			}
		}
		if !hasDirect && req.Mode != "2" && req.Mode != "huiguo" {
			if err := p.AddClient("VPS", flagForIP(sess.remote)+"VPS直连", "xtls-rprx-vision", inboundIDs); err == nil {
				j.log("✓ VPS直连")
			}
		}
		specs, err := toSpecs(req.Exits, clients, xray)
		if err != nil {
			return err
		}
		for _, sp := range specs {
			if err := AddExit(p, sp, inboundIDs); err != nil {
				j.log(fmt.Sprintf("✗ %s：%v", sp.Label, err))
			} else {
				j.log("✓ " + sp.Label)
			}
		}

		j.setStep(5)
		if err := p.RestartXray(); err != nil {
			return err
		}
		if err := VerifyListening(sess.remote); err != nil {
			return err
		}
		j.log("✓ 三条入口都在正常工作")

		basicsOK, fwOK, acmeOK := CheckHardening(sess.remote, sess.info.SSHPort, p.Port)
		j.setStep(6)
		if basicsOK {
			j.log("· 防暴力破解和自动安全更新以前已经开好，跳过")
		} else if err := HardenBasics(sess.remote, sess.info.SSHPort); err != nil {
			j.log("⚠ " + err.Error())
		} else {
			j.log("✓ 已开启防暴力破解和自动安全更新")
		}

		j.setStep(7)
		if fwOK && acmeOK {
			j.log("· 防火墙和证书自动续期以前已经配好，跳过")
		} else {
			if err := ApplyFirewall(sess.remote, sess.info.SSHPort, p.Port); err != nil {
				j.log("⚠ " + err.Error())
			} else {
				j.log(fmt.Sprintf("✓ 防火墙只开放：SSH(%s)、面板(%s)、TCP 443、UDP 443/8443", sess.info.SSHPort, p.Port))
			}
			if hasACME, err := SetupACMEHooks(sess.remote); err != nil {
				j.log("⚠ " + err.Error())
			} else if hasACME {
				j.log("✓ 面板证书会自动续期")
			}
		}

		j.setStep(8)
		files, err := exportAll(p, sess.info.IP, sess.outDir, nil, j.log)
		if err != nil {
			return err
		}
		j.mu.Lock()
		j.Files = files
		j.mu.Unlock()
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiJob(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	j := a.job
	a.mu.Unlock()
	if j == nil {
		writeJSON(w, map[string]any{"ok": true, "job": nil})
		return
	}
	writeJSON(w, map[string]any{
		"ok":  true,
		"job": j.snapshot(),
	})
}

func (a *App) apiExits(w http.ResponseWriter, r *http.Request) {
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	clients, err := p.Clients()
	if err != nil {
		fail(w, err)
		return
	}
	xray, _, err := p.GetXray()
	if err != nil {
		fail(w, err)
		return
	}
	inbounds, err := p.Inbounds()
	if err != nil {
		fail(w, err)
		return
	}
	onlines := p.Onlines()

	a.mu.Lock()
	healthMap := a.healths
	checked := a.healthCheck
	a.mu.Unlock()

	var list []map[string]any
	fixableCount := 0
	nowMs := time.Now().UnixMilli()

	for _, c := range clients {
		china := strings.HasSuffix(c.Comment, "[CN]")
		label := strings.TrimSpace(strings.TrimSuffix(c.Comment, "[CN]"))
		if label == "" {
			label = c.Email
		}
		where, kind := DescribeExit(xray, c, inbounds)
		expStr := ""
		expired := false
		if c.ExpiryTime > 0 {
			expStr = time.UnixMilli(c.ExpiryTime).Format("2006-01-02")
			expired = c.ExpiryTime < nowMs
		}
		lines := BuildLines(c, inbounds, "0.0.0.0", label)
		item := map[string]any{
			"email":   c.Email,
			"label":   label,
			"where":   where,
			"enable":  c.Enable,
			"cn":      china,
			"country": labelCountry(label),
			"kind":    kind,
			"lines":   len(lines),
			"used":    c.Up + c.Down,
			"limit":   c.TotalGB,
			"expires": expStr,
			"expired": expired,
			"online":  onlines[c.Email],
		}
		if eh, ok := healthMap[c.Email]; ok {
			item["health"] = eh
			for _, prob := range eh.Problems {
				if prob.Fixable {
					fixableCount++
					break
				}
			}
		}
		list = append(list, item)
	}

	writeJSON(w, map[string]any{
		"ok":       true,
		"exits":    list,
		"panelUrl": p.PublicURL,
		"idle":     IdleOutbounds(xray),
		"checked":  checked,
		"fixable":  fixableCount,
	})
}

func (a *App) setHealth(list []ExitHealth) {
	m := map[string]ExitHealth{}
	for _, eh := range list {
		m[eh.Email] = eh
	}
	a.mu.Lock()
	a.healths = m
	a.healthCheck = true
	a.mu.Unlock()
}

func healthSummary(list []ExitHealth) string {
	bad, fixable := 0, 0
	for _, eh := range list {
		if eh.Status != "ok" {
			bad++
			for _, prob := range eh.Problems {
				if prob.Fixable {
					fixable++
					break
				}
			}
		}
	}
	if bad == 0 {
		return fmt.Sprintf("—— %d 条线路全部正常 ——", len(list))
	}
	if fixable > 0 {
		return fmt.Sprintf("—— %d 条线路有问题，其中 %d 条可以一键修复（回到线路列表点「一键修复」）——", bad, fixable)
	}
	return fmt.Sprintf("—— %d 条线路有问题，软件改不了，原因和办法写在线路列表里 ——", bad)
}

func (a *App) apiExitHealth(w http.ResponseWriter, r *http.Request) {
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	steps := []string{"逐条检查线路"}
	if err := a.startJob("exitcheck", steps, func(j *Job) error {
		j.setStep(0)
		list, err := CheckExitHealth(sess.remote, p, sess.info.IP, j.log)
		if err != nil {
			return err
		}
		a.setHealth(list)
		j.log(healthSummary(list))
		return nil
	}); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiExitRepair(w http.ResponseWriter, r *http.Request) {
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	steps := []string{"找出问题", "修复", "重启 Xray", "再检查一遍", "更新配置文件"}
	if err := a.startJob("exitfix", steps, func(j *Job) error {
		j.setStep(0)
		list, err := CheckExitHealth(sess.remote, p, sess.info.IP, j.log)
		if err != nil {
			return err
		}
		a.setHealth(list)
		hasFix := false
		for _, eh := range list {
			for _, prob := range eh.Problems {
				if prob.Fixable {
					hasFix = true
					break
				}
			}
			if hasFix {
				break
			}
		}
		if !hasFix {
			j.log("没有软件能自动修的问题。")
			j.log(healthSummary(list))
			return nil
		}
		j.setStep(1)
		if err := RepairExits(p, list, j.log); err != nil {
			return err
		}
		j.setStep(2)
		if err := p.RestartXray(); err != nil {
			return fmt.Errorf("重启 Xray 失败：%v", err)
		}
		j.log("✓ Xray 已重启")
		j.setStep(3)
		j.log("—— 修完再检查一遍 ——")
		list2, err := CheckExitHealth(sess.remote, p, sess.info.IP, j.log)
		if err == nil {
			a.setHealth(list2)
			j.log(healthSummary(list2))
		}
		j.setStep(4)
		files, _ := exportAll(p, sess.info.IP, sess.outDir, nil, j.log)
		j.mu.Lock()
		j.Files = files
		j.OutDir = sess.outDir
		j.mu.Unlock()
		return nil
	}); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiAdoptExit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tag    string `json:"tag"`
		Label  string `json:"label"`
		Region string `json:"region"`
		China  bool   `json:"china"`
	}
	if err := decode(r, &req); err != nil || strings.TrimSpace(req.Tag) == "" {
		fail(w, errors.New("参数不完整"))
		return
	}
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	steps := []string{"建立线路", "重启 Xray", "生成配置文件"}
	china := req.China || isCNRegion(req.Region)
	if err := a.startJob("adopt", steps, func(j *Job) error {
		j.setStep(0)
		clients, err := p.Clients()
		if err != nil {
			return err
		}
		inbounds, err := p.Inbounds()
		if err != nil {
			return err
		}
		var ids []int
		for _, in := range inbounds {
			if (in.Protocol == "vless" && in.Port == 443) || (in.Protocol == "hysteria" && (in.Port == 443 || in.Port == 8443)) {
				ids = append(ids, in.ID)
			}
		}
		xray, _, _ := p.GetXray()
		email := NextExitName(clients, xray)
		label := strings.TrimSpace(req.Label)
		if label == "" {
			label = req.Tag
		}
		if err := AdoptOutbound(p, req.Tag, email, label, china, ids); err != nil {
			return err
		}
		j.log(fmt.Sprintf("✓ 出站「%s」已经配上线路，代号 %s", req.Tag, email))
		j.setStep(1)
		if err := p.RestartXray(); err != nil {
			return err
		}
		j.setStep(2)
		files, err := exportAll(p, sess.info.IP, sess.outDir, nil, j.log)
		if err != nil {
			return err
		}
		j.mu.Lock()
		j.Files = files
		j.OutDir = sess.outDir
		j.mu.Unlock()
		return nil
	}); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiAddExits(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Exits []exitReq `json:"exits"`
	}
	if err := decode(r, &req); err != nil || len(req.Exits) == 0 {
		fail(w, errors.New("没有要添加的住宅 IP"))
		return
	}
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	steps := []string{"写入出口", "重启 Xray", "生成配置文件"}
	if err := a.startJob("add", steps, func(j *Job) error {
		j.setStep(0)
		clients, err := p.Clients()
		if err != nil {
			return err
		}
		inbounds, err := p.Inbounds()
		if err != nil {
			return err
		}
		var ids []int
		for _, in := range inbounds {
			if (in.Protocol == "vless" && in.Port == 443) || (in.Protocol == "hysteria" && (in.Port == 443 || in.Port == 8443)) {
				ids = append(ids, in.ID)
			}
		}
		xray, _, _ := p.GetXray()
		specs, err := toSpecs(req.Exits, clients, xray)
		if err != nil {
			return err
		}
		added := 0
		for _, sp := range specs {
			if err := AddExit(p, sp, ids); err != nil {
				j.log(fmt.Sprintf("✗ %s：%v", sp.Label, err))
			} else {
				added++
				j.log("✓ " + sp.Label)
			}
		}
		if added == 0 {
			return errors.New("一个出口都没有加上")
		}
		j.setStep(1)
		if err := p.RestartXray(); err != nil {
			return err
		}
		j.setStep(2)
		files, err := exportAll(p, sess.info.IP, sess.outDir, nil, j.log)
		if err != nil {
			return err
		}
		j.mu.Lock()
		j.Files = files
		j.OutDir = sess.outDir
		j.mu.Unlock()
		return nil
	}); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiDelExit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decode(r, &req); err != nil || req.Email == "" {
		fail(w, errors.New("没有指定出口"))
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	steps := []string{"删除出口", "重启 Xray"}
	if err := a.startJob("delete", steps, func(j *Job) error {
		j.setStep(0)
		if err := RemoveExit(p, req.Email); err != nil {
			return err
		}
		j.log("✓ 已删除 " + req.Email)
		j.setStep(1)
		return p.RestartXray()
	}); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiExport(w http.ResponseWriter, r *http.Request) {
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	var req struct {
		Emails []string `json:"emails"`
	}
	_ = decode(r, &req)
	steps := []string{"生成配置文件"}
	if err := a.startJob("export", steps, func(j *Job) error {
		j.setStep(0)
		writePanelInfo(sess.outDir, p, sess.info)
		files, err := exportAll(p, sess.info.IP, sess.outDir, req.Emails, j.log)
		if err != nil {
			return err
		}
		j.mu.Lock()
		j.Files = files
		j.OutDir = sess.outDir
		j.mu.Unlock()
		return nil
	}); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiCheckup(w http.ResponseWriter, r *http.Request) {
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	steps := []string{"体检所有出口"}
	if err := a.startJob("checkup", steps, func(j *Job) error {
		j.setStep(0)
		return checkupTo(sess.remote, p, sess.info.IP, j.log)
	}); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func checkupTo(r *Remote, p *Panel, serverIP string, log func(string)) error {
	xray, _, err := p.GetXray()
	if err != nil {
		return err
	}
	clients, err := p.Clients()
	if err != nil {
		return err
	}
	st, _ := p.XrayState()
	log(fmt.Sprintf("服务器 %s，Xray 状态：%s", serverIP, st))
	count := 0
	for _, c := range clients {
		outTag := OutboundForUser(xray, c.Email)
		if outTag == "" || outTag == "direct" {
			continue
		}
		ob := findOutbound(xray, outTag)
		rp := proxyOf(ob)
		if rp == nil {
			continue
		}
		count++
		pr := ProbeExit(r, rp)
		log(fmt.Sprintf("%s：%s", c.Comment, pr.String()))
	}
	if count == 0 {
		log("还没有住宅出口")
	}
	return nil
}

func (a *App) apiOpen(w http.ResponseWriter, r *http.Request) {
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	openFolder(sess.outDir)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) diagnose(j *Job) error {
	sess, err := a.session()
	if err != nil {
		return err
	}
	findings, summary, err := Diagnose(sess.remote, sess.info, sess.outDir, j.log)
	if err != nil {
		return err
	}
	j.log(summary)
	j.mu.Lock()
	j.Report = findings
	j.OutDir = sess.outDir
	j.mu.Unlock()
	return nil
}

func (a *App) apiDoctor(w http.ResponseWriter, r *http.Request) {
	if _, err := a.session(); err != nil {
		fail(w, err)
		return
	}
	if err := a.startJob("doctor", nil, func(j *Job) error {
		return a.diagnose(j)
	}); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiDoctorFix(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Fixes []string `json:"fixes"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	seen := map[string]bool{}
	var fixes []string
	needRestart := false
	for _, f := range req.Fixes {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		fixes = append(fixes, f)
		if fixNeedsRestart[f] {
			needRestart = true
		}
	}
	if len(fixes) == 0 {
		fail(w, errors.New("没有选择要修复的项目"))
		return
	}

	if err := a.startJob("fix", nil, func(j *Job) error {
		failed := 0
		for _, fx := range fixes {
			if err := RunFix(sess.remote, sess.info, sess.outDir, fx, j.log); err != nil {
				failed++
				j.log("✗ " + fx + "：" + err.Error())
			} else {
				j.log("✓ " + fx)
			}
		}
		if needRestart && !seen["restart"] {
			if p, err := a.loadPanel(); err == nil {
				if err := p.RestartXray(); err != nil {
					j.log("✗ 重启 Xray：" + err.Error())
				} else if err := VerifyListening(sess.remote); err != nil {
					j.log("✗ " + err.Error())
				} else {
					j.log("✓ Xray 已重启，三个端口都在监听")
				}
			}
		}
		a.mu.Lock()
		a.panel = nil
		a.mu.Unlock()
		j.log("—— 重新检测 ——")
		_ = a.diagnose(j)
		if failed > 0 {
			j.log(fmt.Sprintf("有 %d 项没修好，原因见上面的红叉。", failed))
		}
		return nil
	}); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiQuickCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP   string `json:"ip"`
		Port string `json:"port"`
	}
	if err := decode(r, &req); err != nil || strings.TrimSpace(req.IP) == "" {
		fail(w, errors.New("请填写 VPS 的 IP 地址"))
		return
	}
	port := strings.TrimSpace(req.Port)
	if port == "" {
		port = "22"
	}
	sshOK, tlsOK := QuickCheck(strings.TrimSpace(req.IP), port)
	writeJSON(w, map[string]any{
		"ok":  true,
		"ssh": sshOK,
		"tls": tlsOK,
	})
}

type savedLogin struct {
	Password string `json:"p,omitempty"`
	KeyPEM   string `json:"k,omitempty"`
	KeyPass  string `json:"kp,omitempty"`
}

type recentServer struct {
	IP     string  `json:"ip"`
	Port   string  `json:"port"`
	User   string  `json:"user"`
	OS     string  `json:"os"`
	Time   int64   `json:"time"`
	Count  int     `json:"count,omitempty"`
	Times  []int64 `json:"times,omitempty"`
	Secret string  `json:"secret,omitempty"`
}

func (rs *recentServer) setSecret(s *savedLogin) {
	if s == nil {
		rs.Secret = ""
		return
	}
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	enc, err := protectSecret(b)
	if err != nil {
		return
	}
	rs.Secret = base64.StdEncoding.EncodeToString(enc)
}

func (rs recentServer) secret() *savedLogin {
	if rs.Secret == "" {
		return nil
	}
	enc, err := base64.StdEncoding.DecodeString(rs.Secret)
	if err != nil {
		return nil
	}
	plain, err := unprotectSecret(enc)
	if err != nil {
		return nil
	}
	var s savedLogin
	if json.Unmarshal(plain, &s) != nil {
		return nil
	}
	return &s
}

func recentPath() string {
	return filepath.Join(exeDir(), "最近的服务器.json")
}

func loadRecent() []recentServer {
	b, err := os.ReadFile(recentPath())
	if err != nil {
		return nil
	}
	var list []recentServer
	_ = json.Unmarshal(b, &list)
	return list
}

func publicRecent() []map[string]any {
	var out []map[string]any
	for _, r := range loadRecent() {
		out = append(out, map[string]any{
			"ip":    r.IP,
			"port":  r.Port,
			"user":  r.User,
			"os":    r.OS,
			"time":  r.Time,
			"count": r.Count,
			"times": r.Times,
			"saved": r.secret() != nil,
		})
	}
	return out
}

func writeRecent(list []recentServer) {
	if b, err := json.MarshalIndent(list, "", "  "); err == nil {
		_ = os.WriteFile(recentPath(), b, 0600)
	}
}

func saveRecent(entry recentServer, keepSecret bool) {
	existing := loadRecent()
	var rest []recentServer
	for _, old := range existing {
		if old.IP == entry.IP && old.User == entry.User {
			entry.Count = old.Count + 1
			entry.Times = append([]int64{entry.Time}, old.Times...)
			if len(entry.Times) > 10 {
				entry.Times = entry.Times[:10]
			}
			if !keepSecret && entry.Secret == "" {
				entry.Secret = old.Secret
			}
		} else {
			rest = append(rest, old)
		}
	}
	if entry.Count == 0 {
		entry.Count = 1
		entry.Times = []int64{entry.Time}
	}
	all := append([]recentServer{entry}, rest...)
	if len(all) > 12 {
		all = all[:12]
	}
	writeRecent(all)
}

func updateSecret(ip, user, newPass string) {
	list := loadRecent()
	for i := range list {
		if list[i].IP == ip && (user == "" || list[i].User == user) && list[i].Secret != "" {
			list[i].setSecret(&savedLogin{Password: newPass})
			writeRecent(list)
			return
		}
	}
}

func forgetSecret(ip, user string) {
	list := loadRecent()
	for i := range list {
		if list[i].IP == ip && (user == "" || list[i].User == user) {
			list[i].Secret = ""
		}
	}
	writeRecent(list)
}

func forgetRecent(ip, user string) {
	var kept []recentServer
	for _, r := range loadRecent() {
		if r.IP != ip || (user != "" && r.User != user) {
			kept = append(kept, r)
		}
	}
	writeRecent(kept)
}

func openAppWindow(url string) error {
	profileDir := filepath.Join(exeDir(), ".ui")
	args := []string{
		"--app=" + url,
		"--window-size=1120,780",
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
				return nil
			}
		}
	}
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func runGUI() {
	var tok [16]byte
	_, _ = rand.Read(tok[:])
	app := &App{
		token:    hex.EncodeToString(tok[:]),
		lastSeen: time.Now(),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatalBox("无法启动", err.Error())
		return
	}
	url := fmt.Sprintf("http://%s/#t=%s", ln.Addr().String(), app.token)
	srv := &http.Server{Handler: app.routes()}
	go func() {
		_ = srv.Serve(ln)
	}()

	debugFlag := filepath.Join(exeDir(), "调试模式.txt")
	if _, err := os.Stat(debugFlag); err == nil {
		_ = os.WriteFile(filepath.Join(exeDir(), "界面地址.txt"), []byte(url), 0600)
	} else if err := openAppWindow(url); err != nil {
		fatalBox("无法打开窗口", "请手动用浏览器打开：\n"+url)
	}

	for {
		time.Sleep(3 * time.Second)
		app.mu.Lock()
		idle := time.Since(app.lastSeen)
		app.mu.Unlock()
		if idle > 15*time.Second && !app.running() {
			app.mu.Lock()
			if app.sess != nil {
				app.sess.close()
			}
			app.mu.Unlock()
			os.Exit(0)
		}
	}
}

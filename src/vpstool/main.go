package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

const version = "2.8"

var (
	stdinReader = bufio.NewReader(os.Stdin)
	reUnsafeFn  = regexp.MustCompile(`[\\/:*?"<>|\s]+`)
)

type redactWriter struct {
	w       io.Writer
	secrets []string
	buf     []byte
}

func (rw *redactWriter) Write(p []byte) (int, error) {
	rw.buf = append(rw.buf, p...)
	for {
		idx := strings.IndexByte(string(rw.buf), '\n')
		if idx == -1 {
			break
		}
		line := string(rw.buf[:idx+1])
		rw.buf = rw.buf[idx+1:]
		for _, sec := range rw.secrets {
			if sec != "" {
				line = strings.ReplaceAll(line, sec, "***")
			}
		}
		_, _ = io.WriteString(rw.w, line)
	}
	return len(p), nil
}

type session struct {
	remote  *Remote
	info    *ServerInfo
	outDir  string
	logFile *os.File
}

func (s *session) close() {
	if s == nil {
		return
	}
	if s.remote != nil && s.remote.Client != nil {
		_ = s.remote.Client.Close()
	}
	if s.logFile != nil {
		_ = s.logFile.Close()
	}
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func sanitize(s string) string {
	return reUnsafeFn.ReplaceAllString(strings.TrimSpace(s), "_")
}

func ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	line, _ := stdinReader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func askSecret(prompt string) string {
	fmt.Printf("%s（输入时不显示）: ", prompt)
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) == nil {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	line, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(line)
}

func confirm(prompt string, defYes bool) bool {
	hint := "y/N"
	def := "n"
	if defYes {
		hint = "Y/n"
		def = "y"
	}
	ans := strings.ToLower(ask(prompt+" ("+hint+")", def))
	return ans == "y" || ans == "yes" || ans == "1" || ans == "是"
}

func step(cur, total int, title string) {
	fmt.Printf("\n[%d/%d] %s\n", cur, total, title)
}

func connect() (*session, error) {
	fmt.Println("\n—— 连接 VPS ——")
	host := ask("VPS 的 IP 地址", "")
	if host == "" {
		return nil, fmt.Errorf("IP 地址不能为空")
	}
	port := ask("SSH 端口", "22")
	user := ask("SSH 用户名", "root")
	method := ask("登录方式：1) 密码  2) 私钥文件", "1")
	var password, keyPath, keyPass string
	if method == "2" {
		keyPath = strings.Trim(ask("私钥文件路径（可以把文件拖进窗口）", ""), `"`)
		keyPass = askSecret("私钥密码（没有就直接回车）")
	} else {
		password = askSecret("SSH 密码")
	}

	outDir := filepath.Join(exeDir(), "输出", sanitize(host))
	_ = os.MkdirAll(outDir, 0755)
	logFile, _ := os.OpenFile(filepath.Join(outDir, "deploy.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if logFile != nil {
		fmt.Fprintf(logFile, "\n===== %s =====\n", time.Now().Format("2006-01-02 15:04:05"))
	}
	rw := &redactWriter{w: logFile, secrets: []string{password, keyPass}}

	fmt.Println("正在连接...")
	r, err := Dial(host, port, user, password, keyPath, keyPass, func(fp string) bool {
		fmt.Printf("第一次连接这台服务器，它的身份指纹是：\n  %s\n", fp)
		return confirm("确认连接吗", true)
	}, rw)
	if err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		return nil, err
	}
	fmt.Println("✓ 已连接。检查服务器环境...")
	info, err := Preflight(r, host)
	if err != nil {
		_ = r.Client.Close()
		if logFile != nil {
			_ = logFile.Close()
		}
		return nil, err
	}
	fmt.Printf("  系统：%s %s（%s），公网 IP：%s\n", info.OSID, info.OSVer, info.Arch, info.IP)
	return &session{remote: r, info: info, outDir: outDir, logFile: logFile}, nil
}

func askExits(r *Remote, mode string, existing []PClient, xray map[string]any) []ExitSpec {
	var specs []ExitSpec
	fakeClients := append([]PClient{}, existing...)
	modeHint := map[string]string{"1": "海外", "2": "中国", "3": ""}[mode]

	for {
		if len(specs) > 0 && !confirm(fmt.Sprintf("\n要添加%s住宅 IP 吗", "下一个"), false) {
			break
		}
		fmt.Println("把代理商给的信息粘贴成一行，支持这两种格式：")
		fmt.Println("  主机:端口:账号:密码        或   socks5://账号:密码@主机:端口")
		raw := ask("代理", "")
		if raw == "" {
			break
		}
		rp, err := ParseProxyLine(raw)
		if err != nil {
			fmt.Println("  ✗", err)
			continue
		}
		fmt.Println("  正在通过 VPS 测试这个代理，并查询它的真实出口...")
		pr := ProbeExit(r, rp)
		fmt.Println("  →", pr.String())
		if !pr.Reachable && !confirm("  代理连不通，仍然添加吗", false) {
			continue
		}
		china := mode == "2"
		if mode == "3" {
			defPurpose := "1"
			if strings.ToUpper(pr.Country) == "CN" {
				defPurpose = "2"
			}
			fmt.Println("用途：1) 翻墙用（美国/日本等海外 IP）  2) 回国用（中国 IP，海外访问国内网站）")
			china = ask("选择", defPurpose) == "2"
		}
		email := NextExitName(fakeClients, xray)
		countryNames := map[string]string{
			"CN": "中国", "US": "美国", "JP": "日本", "HK": "香港",
			"SG": "新加坡", "TW": "台湾", "KR": "韩国", "GB": "英国", "DE": "德国",
		}
		defLabel := email
		if cn := countryNames[strings.ToUpper(pr.Country)]; cn != "" {
			defLabel = flagFor(pr.Country) + cn + "-" + email
		} else if modeHint != "" {
			defLabel = modeHint + "-" + email
		}
		label := strings.TrimSpace(ask("显示名称", defLabel))
		specs = append(specs, ExitSpec{
			Email: email,
			Label: label,
			China: china,
			Proxy: rp,
		})
		fakeClients = append(fakeClients, PClient{Email: email})
		fmt.Printf("  ✓ 已记下：%s（面板代号 %s）\n", label, email)
	}
	return specs
}

type cfgFile struct {
	label     string
	basePath  string
	clashYAML string
	uriText   string
	lineCount int
	err       error
}

func renderConfigs(clients []PClient, inbounds []Inbound, serverIP, outDir string) []cfgFile {
	var out []cfgFile
	for _, c := range clients {
		if !c.Enable {
			continue
		}
		china := strings.HasSuffix(c.Comment, "[CN]")
		label := strings.TrimSpace(strings.TrimSuffix(c.Comment, "[CN]"))
		if label == "" {
			label = c.Email
		}
		label = withFlag(label)
		lines := BuildLines(c, inbounds, serverIP, label)
		if len(lines) == 0 {
			out = append(out, cfgFile{label: label, err: fmt.Errorf("这个出口没有可用线路")})
			continue
		}
		flag := flagEmoji(labelCountry(label))
		lines = flagLines(lines, flag)
		yamlStr := BuildClash(label, lines, china)
		var uris []string
		for _, li := range lines {
			uris = append(uris, li.URI)
		}
		safeName := fmt.Sprintf("%s_%s", sanitize(stripFlag(label)), sanitize(c.Email))
		out = append(out, cfgFile{
			label:     label,
			basePath:  filepath.Join(outDir, safeName),
			clashYAML: yamlStr,
			uriText:   strings.Join(uris, "\n") + "\n",
			lineCount: len(lines),
		})
	}
	return out
}

func mergedConfigs(clients []PClient, inbounds []Inbound, serverIP, outDir string, selected []string) []cfgFile {
	selMap := map[string]bool{}
	for _, s := range selected {
		selMap[s] = true
	}
	var fqGroups, hgGroups []exitGroup
	for _, c := range clients {
		if !c.Enable {
			continue
		}
		if len(selMap) > 0 && !selMap[c.Email] {
			continue
		}
		china := strings.HasSuffix(c.Comment, "[CN]")
		label := strings.TrimSpace(strings.TrimSuffix(c.Comment, "[CN]"))
		if label == "" {
			label = c.Email
		}
		label = withFlag(label)
		lines := BuildLines(c, inbounds, serverIP, label)
		if len(lines) == 0 {
			continue
		}
		flag := flagEmoji(labelCountry(label))
		lines = flagLines(lines, flag)
		if china {
			hgGroups = append(hgGroups, exitGroup{Label: label, Lines: lines})
		} else {
			fqGroups = append(fqGroups, exitGroup{Label: label, Lines: lines})
		}
	}

	prefix := "全部出口"
	if len(selMap) > 0 {
		prefix = "自选出口"
	}
	var out []cfgFile
	if len(fqGroups) >= 2 || (len(selMap) > 0 && len(fqGroups) >= 1) {
		out = append(out, cfgFile{
			label:     fmt.Sprintf("%d 个出口", len(fqGroups)),
			basePath:  filepath.Join(outDir, fmt.Sprintf("%s_%s_合并", prefix, "翻墙")),
			clashYAML: BuildClashMulti(fqGroups, false),
			lineCount: len(fqGroups),
		})
	}
	if len(hgGroups) >= 2 || (len(selMap) > 0 && len(hgGroups) >= 1) {
		out = append(out, cfgFile{
			label:     fmt.Sprintf("%d 个出口", len(hgGroups)),
			basePath:  filepath.Join(outDir, fmt.Sprintf("%s_%s_合并", prefix, "回国")),
			clashYAML: BuildClashMulti(hgGroups, true),
			lineCount: len(hgGroups),
		})
	}
	return out
}

func exportAll(p *Panel, serverIP, outDir string, selected []string, log func(string)) ([]string, error) {
	time.Sleep(500 * time.Millisecond)
	clients, err := p.Clients()
	if err != nil {
		return nil, err
	}
	inbounds, err := p.Inbounds()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, cf := range renderConfigs(clients, inbounds, serverIP, outDir) {
		if cf.err != nil {
			if log != nil {
				log(fmt.Sprintf("✗ %s：%v", cf.label, cf.err))
			}
			continue
		}
		yamlFile := cf.basePath + ".yaml"
		uriFile := cf.basePath + "_分享链接.txt"
		if err := os.WriteFile(yamlFile, []byte(cf.clashYAML), 0600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(uriFile, []byte(cf.uriText), 0600); err != nil {
			return nil, err
		}
		files = append(files, yamlFile)
		if log != nil {
			log(fmt.Sprintf("✓ %s（%d 条线路）", filepath.Base(yamlFile), cf.lineCount))
		}
	}
	for _, mf := range mergedConfigs(clients, inbounds, serverIP, outDir, selected) {
		yamlFile := mf.basePath + ".yaml"
		if err := os.WriteFile(yamlFile, []byte(mf.clashYAML), 0600); err != nil {
			return nil, err
		}
		files = append(files, yamlFile)
		if log != nil {
			log(fmt.Sprintf("✓ %s（%s合在一个文件里，导入后在 PROXY 分组里点选出口）", filepath.Base(yamlFile), mf.label))
		}
	}
	return files, nil
}

func writePanelInfo(outDir string, p *Panel, info *ServerInfo) {
	content := fmt.Sprintf(`面板信息（请妥善保管，不要发给别人）
==============================
面板地址：%s
用户名：  %s
密码：    %s
API 令牌：%s

服务器：  %s（SSH 端口 %s）
生成时间：%s

说明：
- 国内直连面板地址可能被墙，请先连上自己的 VPN 再打开。
- 面板的用户名和密码可以在本软件的「安全设置」里修改。
- 检查 IP 有没有被墙：https://www.itdog.cn/tcping/%s:443
`, p.PublicURL, p.Username, p.Password, p.APIToken, info.IP, info.SSHPort, time.Now().Format("2006-01-02 15:04"), info.IP)
	_ = os.WriteFile(filepath.Join(outDir, "面板信息.txt"), []byte(content), 0600)
}

func openFolder(dir string) {
	_ = exec.Command("explorer", dir).Start()
}

func flagForIP(r *Remote) string {
	out, _ := r.RunStdin("", "curl -s -m 8 https://ipinfo.io/country || true")
	return flagFor(strings.TrimSpace(out))
}

func deploy() error {
	sess, err := connect()
	if err != nil {
		return err
	}
	defer sess.close()

	if sess.info.HasXUI {
		fmt.Println("\n这台服务器上已经装了 3x-ui。")
		if !confirm("在现有面板上继续配置吗？（不会重装，已有的入站会保留）", true) {
			return nil
		}
	}

	fmt.Println("\n用途模式：")
	fmt.Println(" 1) 翻墙：给在国内的人用（会屏蔽 VPS 访问国内网站，降低被识别风险）")
	fmt.Println(" 2) 回国：给在海外的人用国内 IP 访问国内网站（需要中国住宅 IP）")
	fmt.Println(" 3) 两种都要")
	mode := ask("选择", "1")
	sni := ask("Reality 伪装的网站（一般不用改）", "www.icloud.com")

	var specs []ExitSpec
	if mode == "2" || confirm("\n要现在添加住宅 IP 出口吗", false) {
		specs = askExits(sess.remote, mode, nil, nil)
	}

	fmt.Println("\n—— 即将开始 ——")
	modeNames := map[string]string{"1": "翻墙", "2": "回国", "3": "翻墙+回国"}
	fmt.Printf("服务器 %s，模式 %s，住宅出口 %d 个。整个过程大约 3～8 分钟，期间不要关闭窗口。\n",
		sess.info.IP, modeNames[mode], len(specs))
	if !confirm("开始吗", true) {
		return nil
	}

	step(1, 8, "安装基础组件、开启 BBR 加速")
	if _, err := InstallBase(sess.remote); err != nil {
		return fmt.Errorf("安装基础组件失败：%v", err)
	}

	if sess.info.HasXUI {
		step(2, 8, "跳过安装（已装 3x-ui）")
	} else {
		step(2, 8, "安装 3x-ui 面板（会自动申请面板证书，需要几分钟）")
		if err := InstallXUI(sess.remote, sess.info.IP); err != nil {
			return fmt.Errorf("安装 3x-ui 失败：%v\n详细输出见 %s", err, filepath.Join(sess.outDir, "deploy.log"))
		}
	}

	p, err := LoadPanel(sess.remote, sess.info.IP)
	if err != nil {
		return err
	}
	_, _ = p.XrayState()
	writePanelInfo(sess.outDir, p, sess.info)

	step(3, 8, "创建入口线路：Reality(TCP 443) + Hysteria2(UDP 8443、UDP 443)")
	if err := MakeHy2Cert(sess.remote); err != nil {
		return err
	}
	inboundIDs, err := EnsureInbounds(p, sni, func(msg string) { fmt.Println(" ", msg) })
	if err != nil {
		return err
	}

	step(4, 8, "配置路由规则")
	xray, testURL, err := p.GetXray()
	if err != nil {
		return err
	}
	EnsureBaseRules(xray, mode == "1")
	if err := p.SaveXray(xray, testURL); err != nil {
		return err
	}

	step(5, 8, "创建 VPS 直连出口和住宅出口")
	clients, _ := p.Clients()
	hasDirect := false
	for _, c := range clients {
		if c.Email == "VPS" {
			hasDirect = true
		}
	}
	if !hasDirect && mode != "2" {
		if err := p.AddClient("VPS", flagForIP(sess.remote)+"VPS直连", "xtls-rprx-vision", inboundIDs); err == nil {
			fmt.Println("  ✓ VPS直连")
		}
	}
	for _, sp := range specs {
		if err := AddExit(p, sp, inboundIDs); err != nil {
			fmt.Printf("  ✗ %s：%v\n", sp.Label, err)
		} else {
			fmt.Printf("  ✓ %s\n", sp.Label)
		}
	}

	step(6, 8, "重启 Xray 并检查端口")
	if err := p.RestartXray(); err != nil {
		return err
	}
	if err := VerifyListening(sess.remote); err != nil {
		return err
	}
	fmt.Println("  ✓ 三条入口都在正常监听")

	step(7, 8, "安全加固：防 SSH 暴力破解、自动安全更新")
	if err := HardenBasics(sess.remote, sess.info.SSHPort); err != nil {
		fmt.Println("  ⚠", err)
	} else {
		fmt.Println("  ✓ fail2ban、自动更新已开启")
	}

	step(8, 8, "开启防火墙（只开放必要端口）")
	if err := ApplyFirewall(sess.remote, sess.info.SSHPort, p.Port); err != nil {
		fmt.Println("  ⚠", err)
	} else {
		fmt.Printf("  ✓ 只开放：SSH(%s)、面板(%s)、TCP 443、UDP 443/8443\n", sess.info.SSHPort, p.Port)
	}
	if hasACME, err := SetupACMEHooks(sess.remote); err != nil {
		fmt.Println("  ⚠ 证书续期设置失败：", err)
	} else if hasACME {
		fmt.Println("  ✓ 面板证书自动续期（续期时临时开 80 端口，每天北京时间 04:43 检查）")
	}

	step(8, 8, "生成配置文件")
	if _, err := exportAll(p, sess.info.IP, sess.outDir, nil, func(msg string) { fmt.Println(" ", msg) }); err != nil {
		return err
	}

	fmt.Printf("\n🎉 部署完成！所有文件在：\n  %s\n", sess.outDir)
	fmt.Println("  · 每个出口一个 .yaml：在 Clash Verge / Clash Meta 里「新建 → 本地文件」导入")
	fmt.Println("  · *_分享链接.txt：手机 v2rayNG / Hiddify 等可直接导入")
	fmt.Println("  · 面板信息.txt：面板地址和账号密码（务必保管好）")
	fmt.Printf("  · 检查 IP 是否被墙：https://www.itdog.cn/tcping/%s:443\n", sess.info.IP)
	openFolder(sess.outDir)
	return nil
}

func listExits(p *Panel) ([]PClient, error) {
	clients, err := p.Clients()
	if err != nil {
		return nil, err
	}
	xray, _, _ := p.GetXray()
	for i, c := range clients {
		state := "启用"
		if !c.Enable {
			state = "停用"
		}
		where := "VPS直连"
		if outTag := OutboundForUser(xray, c.Email); outTag != "" && outTag != "direct" {
			if ob := findOutbound(xray, outTag); ob != nil {
				set := asObj(ob["settings"])
				if srvs, ok := set["servers"].([]any); ok && len(srvs) > 0 {
					s0 := asObj(srvs[0])
					where = fmt.Sprintf("%s %s:%s", getStr(ob, "protocol"), getStr(s0, "address"), getStr(s0, "port"))
				}
			}
		}
		fmt.Printf(" %d) %-8s %-22s %s [%s]\n", i+1, c.Email, c.Comment, where, state)
	}
	return clients, nil
}

func checkup(r *Remote, p *Panel, serverIP string) {
	xray, _, err := p.GetXray()
	if err != nil {
		return
	}
	clients, err := p.Clients()
	if err != nil {
		return
	}
	fmt.Printf("VPS 本身：IP %s。是否被墙请看 https://www.itdog.cn/tcping/%s:443\n", serverIP, serverIP)
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
		fmt.Printf("· %s（%s）：", c.Comment, c.Email)
		pr := ProbeExit(r, rp)
		fmt.Println(pr.String())
	}
}

func manage() error {
	sess, err := connect()
	if err != nil {
		return err
	}
	defer sess.close()

	p, err := LoadPanel(sess.remote, sess.info.IP)
	if err != nil {
		return err
	}

	for {
		fmt.Println("\n—— 管理", sess.info.IP, "——")
		fmt.Println(" 1) 查看所有出口")
		fmt.Println(" 2) 添加住宅 IP 出口")
		fmt.Println(" 3) 删除出口")
		fmt.Println(" 4) 重新生成所有配置文件")
		fmt.Println(" 5) 体检：测试每个住宅出口是否可用、真实 IP 和类型")
		fmt.Println(" 0) 返回")
		choice := ask("选择", "")
		switch choice {
		case "0", "":
			return nil
		case "1":
			_, _ = listExits(p)
		case "2":
			clients, _ := p.Clients()
			inbounds, _ := p.Inbounds()
			var ids []int
			for _, in := range inbounds {
				ids = append(ids, in.ID)
			}
			xray, _, _ := p.GetXray()
			specs := askExits(sess.remote, "3", clients, xray)
			for _, sp := range specs {
				if err := AddExit(p, sp, ids); err != nil {
					fmt.Printf("  ✗ %s：%v\n", sp.Label, err)
				} else {
					fmt.Printf("  ✓ %s\n", sp.Label)
				}
			}
			if len(specs) > 0 {
				fmt.Println("重启 Xray（VPN 会断几秒）...")
				_ = p.RestartXray()
				_, _ = exportAll(p, sess.info.IP, sess.outDir, nil, func(msg string) { fmt.Println(" ", msg) })
				openFolder(sess.outDir)
			}
		case "3":
			clients, err := listExits(p)
			if err != nil || len(clients) == 0 {
				continue
			}
			idx, err := strconv.Atoi(ask("要删除的序号", ""))
			if err != nil || idx < 1 || idx > len(clients) {
				continue
			}
			target := clients[idx-1]
			if confirm(fmt.Sprintf("确定删除 %s（%s）吗", target.Comment, target.Email), false) {
				if err := RemoveExit(p, target.Email); err != nil {
					fmt.Println("✗", err)
				} else {
					_ = p.RestartXray()
					fmt.Println("  ✓ 已删除")
				}
			}
		case "4":
			_, _ = exportAll(p, sess.info.IP, sess.outDir, nil, func(msg string) { fmt.Println(" ", msg) })
			openFolder(sess.outDir)
		case "5":
			checkup(sess.remote, p, sess.info.IP)
		}
	}
}

func cliMain() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("\n程序出错：", r)
			fmt.Print("\n按回车键退出...")
			_, _ = stdinReader.ReadString('\n')
		}
	}()
	setupConsole()
	ok, _, reason := loadLicense()
	fmt.Printf("===== VPS 一键部署工具 v%s（3x-ui + Reality + Hysteria2）=====\n", version)
	fmt.Println("你的密码只用于本次连接，不会保存到任何文件。")
	if !ok {
		if reason != "" {
			fmt.Println(reason)
		}
		fmt.Println("本机机器码：" + machineCode())
		fmt.Println("请直接双击程序，在窗口里输入授权码。")
		return
	}
	for {
		fmt.Println("\n========== 主菜单 ==========")
		fmt.Println(" 1) 部署新服务器（全自动）")
		fmt.Println(" 2) 管理已部署的服务器（添加/删除住宅 IP、重新生成配置、体检）")
		fmt.Println(" 0) 退出")
		c := ask("选择", "")
		var err error
		switch c {
		case "0":
			return
		case "1":
			err = deploy()
		case "2":
			err = manage()
		}
		if err != nil {
			fmt.Println("\n✗", err)
		}
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--cli" {
		cliMain()
		return
	}
	runGUI()
}

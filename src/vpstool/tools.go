package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type aiConfig struct {
	Base  string `json:"base"`
	Key   string `json:"key"`
	Model string `json:"model"`
}

var (
	reStrongPass = regexp.MustCompile(`^[A-Za-z0-9!@#%^*_+=.,-]{12,64}$`)
	rePanelUser  = regexp.MustCompile(`^[A-Za-z0-9_]{4,32}$`)

	aiTools = []map[string]any{
		{
			"type": "function",
			"function": map[string]any{
				"name":        "search_knowledge",
				"description": "在知识库里查资料。回答任何和 VPN、服务器、线路、客户端、本软件用法有关的问题之前，先用用户问题里的关键词查一次。",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "关键词，例如「Google Play 转圈」「住宅IP 显示VPS」「朋友 连不上」",
						},
					},
					"required": []string{"query"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "save_note",
				"description": "把值得长期记住的事实记到备忘里，以后每次对话都能看到。例如用户的 VPS 商家和到期日、住宅 IP 代理商、已经解决过的问题和解决办法、用户的使用习惯。不要记密码、密钥。",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"text": map[string]any{
							"type":        "string",
							"description": "一句话，不超过 200 字",
						},
					},
					"required": []string{"text"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "get_status",
				"description": "查看软件当前状态：是否已连接服务器、服务器 IP 和系统、当前在哪个页面、是否有任务在运行。",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
					"required":   []string{},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "navigate",
				"description": "切换到软件的某个页面。需要连接服务器的页面在未连接时会先进入连接页，由用户自己输入密码。",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"page": map[string]any{
							"type":        "string",
							"enum":        []string{"home", "new", "manage", "doctor", "console", "security", "help"},
							"description": "home 首页；new 搭建新服务器；manage 管理线路；doctor 检测并修复；console 控制台；security 安全设置（改密码）；help 帮助",
						},
					},
					"required": []string{"page"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "run_diagnosis",
				"description": "对已连接的服务器运行完整检测（约半分钟），返回发现的问题、建议和可以自动修复的修复项代号。",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
					"required":   []string{},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "apply_fixes",
				"description": "执行检测给出的自动修复项。会先让用户确认。",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"fixes": map[string]any{
							"type":        "array",
							"items":       map[string]any{"type": "string"},
							"description": "run_diagnosis 返回的 fix 代号列表",
						},
					},
					"required": []string{"fixes"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "list_lines",
				"description": "列出服务器上的所有线路：名称、出口、是否启用、是否在线、已用流量、流量上限、到期日。",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
					"required":   []string{},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "get_server_status",
				"description": "查看服务器的 CPU、内存、硬盘、开机时间、流量，以及 Xray 和面板的版本。",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
					"required":   []string{},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "start_deploy",
				"description": "在已连接的服务器上一键搭建 VPN（安装 3x-ui、创建 Reality 和 Hysteria2 入口、防火墙和安全设置、生成配置文件）。会先让用户确认，然后等待搭建完成（3 到 8 分钟）并返回结果。搭建前要先问清用途。住宅 IP 需要用户之后在「管理线路」里自己添加。",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"mode": map[string]any{
							"type":        "string",
							"enum":        []string{"fanqiang", "huiguo", "both"},
							"description": "fanqiang 翻墙（给在国内的人用）；huiguo 回国（给在海外的人访问国内内容）；both 两种都要",
						},
					},
					"required": []string{"mode"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "set_line_limit",
				"description": "修改一条线路的流量上限、到期日或启用状态。会先让用户确认。只传需要修改的参数。",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id": map[string]any{
							"type":        "string",
							"description": "list_lines 返回的线路 id",
						},
						"limit_gb": map[string]any{
							"type":        "number",
							"description": "流量上限，单位 GB，0 表示不限",
						},
						"expires": map[string]any{
							"type":        "string",
							"description": "到期日 YYYY-MM-DD，空字符串表示永久",
						},
						"enabled": map[string]any{
							"type":        "boolean",
							"description": "true 启用，false 停用",
						},
					},
					"required": []string{"id"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "backup_panel",
				"description": "把面板数据库备份到用户电脑的「输出」文件夹。",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
					"required":   []string{},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "run_command",
				"description": "在已连接的 VPS 上执行一条 shell 命令并返回输出。每次都会先把命令展示给用户确认。只用于排查和用户明确要求的操作；不能运行需要交互的程序（vim、top 等）。",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"command": map[string]any{
							"type": "string",
						},
						"reason": map[string]any{
							"type":        "string",
							"description": "用一句中文告诉用户为什么要执行",
						},
					},
					"required": []string{"command", "reason"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "panel_api_search",
				"description": "在 3x-ui 面板自带的接口文档里按英文关键词查接口，返回方法、路径、说明和请求体格式。调用 panel_api_call 之前必须先查，不要凭记忆猜路径和参数。",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "英文关键词，空格分开，例如 clients traffic reset、inbounds add、setting、backup、xray outbound",
						},
					},
					"required": []string{"query"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "panel_api_call",
				"description": "调用 3x-ui 面板的任意接口，用来完成本软件按钮没有覆盖的面板功能（流量上限和到期时间、停用启用、重置流量、新增其它协议的入站、面板设置、备份等）。GET 直接执行；POST 会先把内容展示给用户确认。返回内容里的密码、密钥、UUID、分享链接会被隐藏。",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"method": map[string]any{
							"type": "string",
							"enum": []string{"GET", "POST"},
						},
						"path": map[string]any{
							"type":        "string",
							"description": "以 /panel/api/ 开头的路径",
						},
						"body": map[string]any{
							"type":        "object",
							"description": "POST 的 JSON 请求体",
						},
						"reason": map[string]any{
							"type":        "string",
							"description": "用一句中文告诉用户这一步要做什么",
						},
					},
					"required": []string{"method", "path", "reason"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "open_panel",
				"description": "在用户的浏览器里打开 3x-ui 面板的登录页（用户名和密码在「面板信息.txt」里，由用户自己输入）。",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
					"required":   []string{},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "regenerate_configs",
				"description": "重新生成所有线路的配置文件到「输出」文件夹。",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
					"required":   []string{},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "open_output_folder",
				"description": "在用户电脑上打开存放配置文件的「输出」文件夹。",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
					"required":   []string{},
				},
			},
		},
	}
)

func (a *App) apiExec(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Cmd string `json:"Cmd"`
		Cwd string `json:"Cwd"`
	}
	if err := decode(r, &req); err != nil || strings.TrimSpace(req.Cmd) == "" {
		fail(w, fmt.Errorf("命令不能为空"))
		return
	}
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	if a.running() {
		fail(w, fmt.Errorf("当前有任务正在执行，请稍候"))
		return
	}
	stopBeat := a.beat()
	defer stopBeat()

	if strings.TrimSpace(req.Cwd) != "" {
		sess.remote.cwd = strings.TrimSpace(req.Cwd)
	}
	out, code, cwd, err := sess.remote.Exec(req.Cmd, 60*time.Second)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"ok":   true,
		"out":  out,
		"code": code,
		"cwd":  cwd,
	})
}

func checkPassword(pw string) error {
	if !reStrongPass.MatchString(pw) {
		return fmt.Errorf("密码需要 12～64 位字母、数字或常见符号")
	}
	var hasUpper, hasLower, hasDigit bool
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("密码需同时包含大写字母、小写字母和数字")
	}
	return nil
}

func (a *App) apiPasswd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target   string `json:"Target"`
		User     string `json:"User"`
		Password string `json:"Password"`
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
	if a.running() {
		fail(w, fmt.Errorf("当前有任务正在执行，请稍候"))
		return
	}
	if err := checkPassword(req.Password); err != nil {
		fail(w, err)
		return
	}

	switch req.Target {
	case "ssh":
		qUser := "'" + strings.ReplaceAll(sess.remote.User, "'", `'\''`) + "'"
		cmd := fmt.Sprintf("printf '%%s:%%s\\n' %s \"$DATA\" | chpasswd && echo PW_OK", qUser)
		out, err := sess.remote.RunStdin(req.Password, cmd)
		if err != nil || !strings.Contains(out, "PW_OK") {
			fail(w, fmt.Errorf("修改失败：%v", err))
			return
		}
		sess.remote.Password = req.Password
		verified := "no"
		if sess.remote.CanConnectFresh() {
			verified = "yes"
		}
		updateSecret(sess.info.IP, sess.remote.User, req.Password)
		if sess.logFile != nil {
			_, _ = fmt.Fprintf(sess.logFile, "[%s] 已修改 %s 的 SSH 登录密码\n", time.Now().Format("15:04:05"), sess.remote.User)
		}
		writeJSON(w, map[string]any{
			"ok":       true,
			"user":     sess.remote.User,
			"verified": verified,
		})

	case "panel":
		if !rePanelUser.MatchString(req.User) {
			fail(w, fmt.Errorf("面板用户名需要 4～32 位字母、数字或下划线"))
			return
		}
		stdinData := req.User + "\n" + req.Password
		script := `
U=$(printf '%s\n' "$DATA" | sed -n 1p)
P=$(printf '%s\n' "$DATA" | sed -n 2p)
/usr/local/x-ui/x-ui setting -username "$U" -password "$P" >/dev/null && systemctl restart x-ui && echo PANEL_OK`
		out, err := sess.remote.RunStdin(stdinData, script)
		if err != nil || !strings.Contains(out, "PANEL_OK") {
			fail(w, fmt.Errorf("修改失败：%v", err))
			return
		}
		a.mu.Lock()
		a.panel = nil
		a.mu.Unlock()
		p, err := a.loadPanel()
		if err == nil {
			p.Username = req.User
			p.Password = req.Password
			writePanelInfo(sess.outDir, p, sess.info)
		}
		if sess.logFile != nil {
			_, _ = fmt.Fprintf(sess.logFile, "[%s] 已修改面板的用户名和密码\n", time.Now().Format("15:04:05"))
		}
		panelURL := ""
		if p != nil {
			panelURL = p.PublicURL
		}
		writeJSON(w, map[string]any{
			"ok":       true,
			"user":     req.User,
			"panelUrl": panelURL,
		})

	default:
		fail(w, fmt.Errorf("未知的修改目标"))
	}
}

func (a *App) apiSecurity(w http.ResponseWriter, r *http.Request) {
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	script := `echo "PWAUTH=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')"
echo "F2B=$(systemctl is-active fail2ban 2>/dev/null)"
echo "FW=$(nft list table inet vpsfw >/dev/null 2>&1 && echo yes || echo no)"
echo "UU=$(grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades && echo yes || echo no)"
echo "XUI=$([ -x /usr/local/x-ui/x-ui ] && echo yes || echo no)"
echo "PUSER=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | awk -F': *' '/^username:/{print $2}')"`
	out, err := sess.remote.RunStdin("", script)
	if err != nil {
		fail(w, err)
		return
	}
	env := parseEnvFile(out)
	writeJSON(w, map[string]any{
		"ok":         true,
		"sshUser":    sess.remote.User,
		"byKey":      sess.remote.ByKey,
		"pwAuth":     env["PWAUTH"] == "yes",
		"fail2ban":   env["F2B"] == "active",
		"firewall":   env["FW"] == "yes",
		"autoUpdate": env["UU"] == "yes",
		"xui":        env["XUI"] == "yes",
		"panelUser":  env["PUSER"],
	})
}

func aiPath() string {
	return filepath.Join(exeDir(), "AI设置.json")
}

func loadAI() aiConfig {
	var cfg aiConfig
	if b, err := os.ReadFile(aiPath()); err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	if norm, _, err := normalizeBase(cfg.Base); err == nil {
		cfg.Base = norm
	}
	return cfg
}

func saveAI(cfg aiConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(aiPath(), b, 0600)
}

func keyHint(k string) string {
	if len(k) <= 8 {
		return "…"
	}
	return k[:4] + "…" + k[len(k)-4:]
}

func (a *App) apiAIConfig(w http.ResponseWriter, r *http.Request) {
	cfg := loadAI()
	writeJSON(w, map[string]any{
		"ok":      true,
		"base":    cfg.Base,
		"model":   cfg.Model,
		"hasKey":  cfg.Key != "",
		"keyHint": keyHint(cfg.Key),
	})
}

func (a *App) apiAISave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Base  string `json:"base"`
		Key   string `json:"key"`
		Model string `json:"model"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	base, note, err := normalizeBase(req.Base)
	if err != nil {
		fail(w, err)
		return
	}
	old := loadAI()
	model := strings.Trim(strings.TrimSpace(req.Model), `"'“”‘’`+"`")
	if model == "" {
		fail(w, fmt.Errorf("请填写模型名称"))
		return
	}
	key := old.Key
	if strings.TrimSpace(req.Key) != "" {
		k, err := cleanKey(req.Key)
		if err != nil {
			fail(w, err)
			return
		}
		if a.isPanelToken(k) {
			fail(w, fmt.Errorf("你填的是 3x-ui 面板的「API 令牌」，它只能用来管理面板，不是 AI 的密钥。\nAI 的密钥要到 AI 服务商的网站上创建（比如 DeepSeek：登录 platform.deepseek.com，在 API keys 里新建），是 sk- 开头的一长串。"))
			return
		}
		key = k
	}
	if key == "" {
		fail(w, fmt.Errorf("请填写 API 密钥"))
		return
	}
	cfg := aiConfig{Base: base, Key: key, Model: model}
	if err := saveAI(cfg); err != nil {
		fail(w, fmt.Errorf("保存失败：%v", err))
		return
	}
	writeJSON(w, map[string]any{
		"ok":      true,
		"base":    cfg.Base,
		"model":   cfg.Model,
		"note":    note,
		"hasKey":  true,
		"keyHint": keyHint(cfg.Key),
	})
}

func (a *App) apiAICheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Base  string `json:"base"`
		Key   string `json:"key"`
		Model string `json:"model"`
	}
	_ = decode(r, &req)
	cfg := loadAI()
	if strings.TrimSpace(req.Base) != "" {
		b, _, err := normalizeBase(req.Base)
		if err != nil {
			fail(w, err)
			return
		}
		cfg.Base = b
	}
	if strings.TrimSpace(req.Model) != "" {
		cfg.Model = strings.TrimSpace(req.Model)
	}
	if strings.TrimSpace(req.Key) != "" {
		k, err := cleanKey(req.Key)
		if err != nil {
			fail(w, err)
			return
		}
		cfg.Key = k
	}
	if a.isPanelToken(cfg.Key) {
		fail(w, fmt.Errorf("你填的是 3x-ui 面板的「API 令牌」，它只能用来管理面板，不是 AI 的密钥。\nAI 的密钥要到 AI 服务商的网站上创建（比如 DeepSeek：登录 platform.deepseek.com，在 API keys 里新建），是 sk- 开头的一长串。"))
		return
	}
	stopBeat := a.beat()
	defer stopBeat()

	level, text, models, err := aiCheck(&cfg)
	if err != nil {
		writeJSON(w, map[string]any{
			"ok":     false,
			"err":    err.Error(),
			"base":   cfg.Base,
			"models": models,
		})
		return
	}
	writeJSON(w, map[string]any{
		"ok":     true,
		"level":  level,
		"text":   text,
		"base":   cfg.Base,
		"models": models,
	})
}

func (a *App) beat() func() {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				a.mu.Lock()
				a.lastSeen = time.Now()
				a.mu.Unlock()
			}
		}
	}()
	return func() {
		close(stop)
	}
}

const aiBasePrompt = `你是「云朵喵 VPN 搭建助手」这款桌面软件里的 AI 助手，用简体中文、口语化地回答，面向完全不懂技术的用户，回答要短、给具体步骤。

软件功能：通过 SSH 登录用户自己的 VPS（Ubuntu/Debian），一键安装 3x-ui 面板，创建三条入口：Reality（TCP 443）、Hysteria2（UDP 443 和 8443）；可为每条线路配置住宅 IP 出口；开启 nftables 防火墙、fail2ban、自动安全更新、BBR；生成 Clash 配置文件（.yaml）和手机分享链接，放在程序旁的「输出」文件夹。
页面：首页、搭建新服务器、管理线路（服务器状态、每条线路的流量和在线情况、设置流量上限和到期日、增删住宅 IP、体检、备份面板、重新生成配置）、检测并修复、控制台（执行命令）、安全设置（改 SSH 密码和面板账号密码）、帮助。

常见问题要点：
- TCP 443 连不上多半是 IP 被墙，改用 Hysteria2 线路；UDP 也不通只能在商家后台换 IP。
- 只有个别人连不上：更新 Clash Verge Rev、校准设备时间、换另一种协议的线路、重新导入最新配置文件、开 TUN 模式并关掉其它加速器。
- Google Play 转圈、住宅出口显示成 VPS 的 IP：运行检测并修复「路由规则」。
- 住宅出口连不上：住宅 IP 到期、账号密码变了，或需要把 VPS 的 IP 加入代理商白名单。
- 面板打不开：国内直连可能被墙，先连上自己的 VPN；证书问题运行检测修复。

你可以调用工具来操作这个软件。规则：
- 回答 VPN、服务器、线路、客户端相关的问题时，先调用 search_knowledge 查知识库，以知识库内容为准；标注「用户补充」的资料优先于内置文章。知识库里没有的，可以用你自己的知识回答，但要说明这是一般性建议。
- 用户提到值得长期记住的事实，或者一个问题刚被解决，调用 save_note 记下来。
- 新手说想搭建但不知道怎么做：先查知识库的「从零开始」，用几句话讲清整体流程，问清两件事——有没有买好 VPS（没有就给选购建议）、用途是翻墙还是回国。然后用 navigate 带他到 new 页面自己填 IP 和密码连接；连接成功后（get_status 确认）调用 start_deploy。搭建完告诉他怎么导入配置文件，并建议改 root 密码。
- 用户问用什么协议、怎么配置更好、3x-ui 有什么功能：先查知识库再给明确建议，不要罗列一堆选项让小白自己选。本软件默认的 Reality + Hysteria2 组合对绝大多数人就是最优解。
- 遇到「连不上/变慢/出错」类问题，优先调用 run_diagnosis，再根据结果解释或调用 apply_fixes。
- 你不能替用户输入任何密码；需要连接服务器或改密码时，用 navigate 带用户到对应页面，让他自己填。
- 面板功能：本软件的按钮只覆盖常用操作。其它 3x-ui 功能用 panel_api_search 查接口、再用 panel_api_call 完成；改动入站、路由、出站之后提醒用户运行一次「检测并修复」确认没有破坏原有线路。不要删除或修改本软件创建的三条入口（标签 in-443-tcp、in-8443-udp、in-443-udp）和它的路由规则，除非用户明确要求。
- run_command 只在确有必要时用，一次一条，优先只读命令；不要执行会断开 SSH、清空数据或关闭防火墙的命令，除非用户明确要求。
- 不要编造工具没有返回的信息；工具报错就如实告诉用户。
- 不要向用户索要或复述密码、API 令牌等敏感信息。

`

func (a *App) aiSystemPrompt() string {
	a.mu.Lock()
	var connState string
	if a.sess != nil && a.sess.info != nil {
		connState = fmt.Sprintf("当前已连接服务器 %s（%s %s），3x-ui 已安装：%v。",
			a.sess.info.IP, a.sess.info.OSID, a.sess.info.OSVer, a.sess.info.HasXUI)
	} else {
		connState = "当前没有连接任何服务器。"
	}
	a.mu.Unlock()
	return aiBasePrompt + connState + kbPromptPart()
}

func (a *App) apiAIChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Messages []map[string]any `json:"messages"`
		NoTools  bool             `json:"noTools"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, err)
		return
	}
	cfg := loadAI()
	if cfg.Base == "" || cfg.Key == "" || cfg.Model == "" {
		fail(w, fmt.Errorf("请先点右上角「设置」填好 AI 的地址、密钥和模型"))
		return
	}
	if a.isPanelToken(cfg.Key) {
		fail(w, fmt.Errorf("你填的是 3x-ui 面板的「API 令牌」，不是 AI 密钥"))
		return
	}
	stopBeat := a.beat()
	defer stopBeat()

	modelKey := cfg.Base + "|" + cfg.Model
	a.mu.Lock()
	noTools := req.NoTools || a.noToolModels[modelKey]
	a.mu.Unlock()

	sysPrompt := a.aiSystemPrompt()
	if noTools {
		sysPrompt += "\n\n注意：当前接入的模型不支持工具调用，你不能直接操作软件，只能用文字回答，并告诉用户在软件里该点哪里。"
	}

	msgs := make([]map[string]any, 0, len(req.Messages)+1)
	msgs = append(msgs, map[string]any{
		"role":    "system",
		"content": sysPrompt,
	})
	msgs = append(msgs, req.Messages...)

	payload := map[string]any{
		"model":    cfg.Model,
		"messages": msgs,
	}
	if !noTools {
		payload["tools"] = aiTools
	}

	resp, err := aiPost(&cfg, payload, 90*time.Second)
	if err != nil {
		fail(w, err)
		return
	}

	if resp.Status != 200 && !noTools && !resp.isHTML() && looksLikeToolErr(aiErrText(resp.Body)) {
		noTools = true
		a.mu.Lock()
		if a.noToolModels == nil {
			a.noToolModels = map[string]bool{}
		}
		a.noToolModels[modelKey] = true
		a.mu.Unlock()

		msgs[0]["content"] = a.aiSystemPrompt() + "\n\n注意：当前接入的模型不支持工具调用，你不能直接操作软件，只能用文字回答，并告诉用户在软件里该点哪里。"
		delete(payload, "tools")
		resp, err = aiPost(&cfg, payload, 90*time.Second)
		if err != nil {
			fail(w, err)
			return
		}
	}

	if resp.Status != 200 || resp.isHTML() {
		fail(w, explainAI(resp, cfg.Model))
		return
	}
	var ch aiChoice
	if err := json.Unmarshal(resp.Body, &ch); err != nil || len(ch.Choices) == 0 {
		fail(w, explainAI(resp, cfg.Model))
		return
	}
	msg := ch.Choices[0].Message
	outMsg := map[string]any{
		"role":    "assistant",
		"content": msg["content"],
	}
	if tc, ok := msg["tool_calls"]; ok {
		outMsg["tool_calls"] = tc
	}
	if rc, ok := msg["reasoning_content"]; ok {
		outMsg["reasoning_content"] = rc
	}
	writeJSON(w, map[string]any{
		"ok":      true,
		"message": outMsg,
		"noTools": noTools,
	})
}

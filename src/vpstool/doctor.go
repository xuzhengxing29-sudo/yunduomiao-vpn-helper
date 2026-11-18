package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Finding struct {
	ID     string `json:"id"`
	Group  string `json:"group"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Advice string `json:"advice"`
	Fix    string `json:"fix"`
}

type doctor struct {
	remote    *Remote
	info      *ServerInfo
	outDir    string
	log       func(string)
	env       map[string]string
	clockSkew int64
	panel     *Panel
	xray      map[string]any
	inbounds  []Inbound
	clients   []PClient
	findings  []Finding
}

var (
	fixPriority = map[string]int{
		"xui":            1,
		"hy2cert":        2,
		"inbounds":       3,
		"inbound_enable": 4,
		"attach":         5,
		"client_enable":  6,
		"routing":        7,
		"dangling":       8,
		"restart":        9,
		"ntp":            10,
		"bbr":            11,
		"swap":           12,
		"disk":           13,
		"harden":         14,
		"firewall":       15,
		"cert":           16,
		"configs":        17,
	}

	fixNeedsRestart = map[string]bool{
		"hy2cert":        true,
		"inbounds":       true,
		"inbound_enable": true,
		"attach":         true,
		"client_enable":  true,
		"routing":        true,
		"dangling":       true,
	}
)

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func routingBroken(xray map[string]any) (blockCN bool, broken bool) {
	routing, _ := xray["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	for _, item := range rules {
		if rm, ok := item.(map[string]any); ok && isCNBlockRule(rm) {
			blockCN = true
			break
		}
	}
	cp := deepCopy(xray)
	EnsureBaseRules(cp, blockCN)
	b1, _ := json.Marshal(xray["routing"])
	b2, _ := json.Marshal(cp["routing"])
	return blockCN, string(b1) != string(b2)
}

func (d *doctor) gather() error {
	script := `
echo "XUI=$(systemctl is-active x-ui 2>/dev/null)"
echo "NTP=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
echo "EPOCH=$(date +%s)"
echo "CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
echo "F2B=$(systemctl is-active fail2ban 2>/dev/null)"
if nft list table inet vpsfw >/dev/null 2>&1; then
  echo FW=yes
  echo "FWT=$(nft list chain inet vpsfw input 2>/dev/null | grep 'tcp dport' | grep -v acme-tmp | head -n1 | tr -dc '0-9, ')"
else echo FW=no; fi
echo "UU=$(grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades && echo yes || echo no)"
echo "DISK=$(df -P / | awk 'NR==2{gsub("%","",$5);print $5}')"
awk '/^MemTotal/{print "MEMT="int($2/1024)} /^MemAvailable/{print "MEMA="int($2/1024)} /^SwapTotal/{print "SWAP="int($2/1024)}' /proc/meminfo
echo "HY2CERT=$([ -s /root/cert/hy2/server.crt ] && [ -s /root/cert/hy2/server.key ] && echo yes || echo no)"
for x in "T443 -tln 443" "U443 -uln 443" "U8443 -uln 8443"; do
  set -- $x; ss $2 2>/dev/null | grep -q ":$3 " && echo "$1=yes" || echo "$1=no"
done
CERT=$(/usr/local/x-ui/x-ui setting -getCert true 2>/dev/null | awk -F': *' '/^cert:/{print $2}')
if [ -n "$CERT" ] && [ -f "$CERT" ]; then
  END=$(openssl x509 -enddate -noout -in "$CERT" 2>/dev/null | cut -d= -f2)
  echo PCERT=yes; echo "PCERTSEC=$(( $(date -d "$END" +%s) - $(date +%s) ))"
else echo PCERT=no; fi
CONF=$(ls /root/.acme.sh/*_ecc/*.conf 2>/dev/null | head -n1)
if [ -n "$CONF" ]; then echo ACME=yes; grep -q open80 "$CONF" && echo HOOK=yes || echo HOOK=no; else echo ACME=no; fi
echo "REBOOT=$([ -f /var/run/reboot-required ] && echo yes || echo no)"
echo "SSHFAIL=$(journalctl -u ssh -u sshd --since '24 hours ago' --no-pager 2>/dev/null | grep -cE 'Failed password|Invalid user')"
echo "BANNED=$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/{gsub(/[ \t]/,"",$2);print $2}')"
echo "PWAUTH=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')"
echo "XLOG=$(journalctl -u x-ui --since '6 hours ago' --no-pager 2>/dev/null | grep -ciE 'address already in use|panic|failed to start')"
true`
	out, err := d.remote.RunStdin("", script)
	if err != nil {
		return fmt.Errorf("读取服务器状态失败：%v", err)
	}
	d.env = parseEnvFile(out)
	if ep, err := strconv.ParseInt(d.env["EPOCH"], 10, 64); err == nil && ep > 0 {
		diff := time.Now().Unix() - ep
		if diff < 0 {
			diff = -diff
		}
		d.clockSkew = diff
	}
	if p, err := LoadPanel(d.remote, d.info.IP); err == nil {
		d.panel = p
		d.xray, _, _ = p.GetXray()
		d.inbounds, _ = p.Inbounds()
		d.clients, _ = p.Clients()
	}
	return nil
}

func num(s string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(s))
	return v
}

func (d *doctor) checkSystem() {
	ntp := d.env["NTP"] == "yes"
	switch {
	case d.clockSkew > 90 && !ntp:
		d.findings = append(d.findings, Finding{
			ID:     "clock",
			Group:  "网络连通",
			Title:  "服务器时间不准",
			Status: "bad",
			Detail: fmt.Sprintf("服务器和你的电脑相差 %d 秒，而且服务器没有开启自动对时。", d.clockSkew),
			Advice: "时间差太大时，客户端会握手失败、整条线路连不上。",
			Fix:    "ntp",
		})
	case d.clockSkew > 90 && ntp:
		d.findings = append(d.findings, Finding{
			ID:     "clock",
			Group:  "网络连通",
			Title:  "你电脑的时间不准",
			Status: "bad",
			Detail: fmt.Sprintf("服务器已自动对时，但你的电脑和它相差 %d 秒。", d.clockSkew),
			Advice: "打开 Windows「设置 → 时间和语言 → 日期和时间」，点「立即同步」。手机同理，打开「自动设置时间」。",
		})
	case !ntp:
		d.findings = append(d.findings, Finding{
			ID:     "clock",
			Group:  "网络连通",
			Title:  "服务器没有开启自动对时",
			Status: "warn",
			Detail: "现在时间还准，但时间久了可能会漂移，导致连不上。",
			Fix:    "ntp",
		})
	default:
		d.findings = append(d.findings, Finding{
			ID:     "clock",
			Group:  "网络连通",
			Title:  "时间同步正常",
			Status: "ok",
			Detail: fmt.Sprintf("服务器和你的电脑相差 %d 秒。", d.clockSkew),
		})
	}

	cc := strings.TrimSpace(d.env["CC"])
	if cc == "" {
		cc = "未知"
	}
	if cc == "bbr" {
		d.findings = append(d.findings, Finding{
			ID:     "bbr",
			Group:  "服务器状态",
			Title:  "BBR 网络加速已开启",
			Status: "ok",
			Detail: "当前拥塞控制算法：bbr",
		})
	} else {
		d.findings = append(d.findings, Finding{
			ID:     "bbr",
			Group:  "服务器状态",
			Title:  "没有开启 BBR 网络加速",
			Status: "warn",
			Detail: "当前拥塞控制算法：" + cc,
			Advice: "BBR 能明显改善高延迟线路的速度，开启后无需重启。",
			Fix:    "bbr",
		})
	}

	disk := num(d.env["DISK"])
	switch {
	case disk >= 90:
		d.findings = append(d.findings, Finding{
			ID:     "disk",
			Group:  "服务器状态",
			Title:  "硬盘快满了",
			Status: "bad",
			Detail: fmt.Sprintf("系统盘已用 %d%%。硬盘满了面板和 Xray 都会出错。", disk),
			Fix:    "disk",
		})
	case disk >= 80:
		d.findings = append(d.findings, Finding{
			ID:     "disk",
			Group:  "服务器状态",
			Title:  "硬盘空间偏紧",
			Status: "warn",
			Detail: fmt.Sprintf("系统盘已用 %d%%。", disk),
			Fix:    "disk",
		})
	default:
		d.findings = append(d.findings, Finding{
			ID:     "disk",
			Group:  "服务器状态",
			Title:  "硬盘空间充足",
			Status: "ok",
			Detail: fmt.Sprintf("已用 %d%%。", disk),
		})
	}

	memT := num(d.env["MEMT"])
	memA := num(d.env["MEMA"])
	swap := num(d.env["SWAP"])
	switch {
	case memT > 0 && memA < 100 && swap == 0:
		d.findings = append(d.findings, Finding{
			ID:     "mem",
			Group:  "服务器状态",
			Title:  "可用内存太少",
			Status: "bad",
			Detail: fmt.Sprintf("总内存 %d MB，只剩 %d MB 可用，Xray 可能被系统杀掉导致断线。", memT, memA),
			Advice: "一键修复会加 1GB 虚拟内存（swap）。",
			Fix:    "swap",
		})
	case memT > 0 && memT < 1200 && swap == 0:
		d.findings = append(d.findings, Finding{
			ID:     "mem",
			Group:  "服务器状态",
			Title:  "小内存服务器没有虚拟内存",
			Status: "warn",
			Detail: fmt.Sprintf("总内存 %d MB，没有 swap。系统自动更新时可能内存不够。", memT),
			Fix:    "swap",
		})
	default:
		d.findings = append(d.findings, Finding{
			ID:     "mem",
			Group:  "服务器状态",
			Title:  "内存正常",
			Status: "ok",
			Detail: fmt.Sprintf("总内存 %d MB，可用 %d MB，虚拟内存 %d MB。", memT, memA, swap),
		})
	}

	if d.env["REBOOT"] == "yes" {
		d.findings = append(d.findings, Finding{
			ID:     "reboot",
			Group:  "服务器状态",
			Title:  "系统更新后需要重启",
			Status: "info",
			Detail: "自动安全更新装了新内核，重启后才生效。",
			Advice: "找个不用 VPN 的时间，在 VPS 商家后台点一次重启，VPN 会自动恢复。",
		})
	}
}

func (d *doctor) checkVPN() {
	if d.env["XUI"] != "active" {
		d.findings = append(d.findings, Finding{
			ID:     "xui",
			Group:  "VPN 服务",
			Title:  "3x-ui 面板服务没有运行",
			Status: "bad",
			Detail: "状态：" + d.env["XUI"] + "。面板停了，Xray 也会跟着停，所有线路都连不上。",
			Fix:    "xui",
		})
		return
	}
	if d.panel == nil {
		d.findings = append(d.findings, Finding{
			ID:     "panel",
			Group:  "VPN 服务",
			Title:  "面板接口连不上",
			Status: "bad",
			Advice: "重启面板通常能解决。如果一直不行，可能是 3x-ui 版本太旧，在服务器上运行 x-ui update。",
			Fix:    "xui",
		})
		return
	}
	d.findings = append(d.findings, Finding{
		ID:     "xui",
		Group:  "VPN 服务",
		Title:  "3x-ui 面板服务运行中",
		Status: "ok",
	})

	st, errMsg := d.panel.XrayState()
	if st == "running" {
		d.findings = append(d.findings, Finding{
			ID:     "xray",
			Group:  "VPN 服务",
			Title:  "Xray 内核运行中",
			Status: "ok",
		})
	} else {
		if st == "" {
			st = "未知"
		}
		detail := "状态：" + st
		if errMsg != "" {
			detail += "，错误：" + errMsg
		} else if num(d.env["XLOG"]) > 0 {
			detail += "。日志里有端口被占用或崩溃记录。"
		}
		d.findings = append(d.findings, Finding{
			ID:     "xray",
			Group:  "VPN 服务",
			Title:  "Xray 内核没有运行",
			Status: "bad",
			Detail: detail,
			Fix:    "restart",
		})
	}

	var missingIn, disabledIn, notListening []string
	hasReal := false
	hasHy := map[int]bool{}
	for _, in := range d.inbounds {
		if in.Protocol == "vless" && in.Port == 443 {
			hasReal = true
			if !in.Enable {
				disabledIn = append(disabledIn, "Reality(TCP 443)")
			} else if d.env["T443"] != "yes" {
				notListening = append(notListening, "Reality(TCP 443)")
			}
		}
		if in.Protocol == "hysteria" && (in.Port == 443 || in.Port == 8443) {
			hasHy[in.Port] = true
			name := fmt.Sprintf("Hysteria2(UDP %d)", in.Port)
			envKey := fmt.Sprintf("U%d", in.Port)
			if !in.Enable {
				disabledIn = append(disabledIn, name)
			} else if d.env[envKey] != "yes" {
				notListening = append(notListening, name)
			}
		}
	}
	if !hasReal {
		missingIn = append(missingIn, "Reality(TCP 443)")
	}
	if !hasHy[8443] {
		missingIn = append(missingIn, "Hysteria2(UDP 8443)")
	}
	if !hasHy[443] {
		missingIn = append(missingIn, "Hysteria2(UDP 443)")
	}

	if len(missingIn) > 0 {
		d.findings = append(d.findings, Finding{
			ID:     "inbounds",
			Group:  "VPN 服务",
			Title:  "缺少入口线路",
			Status: "bad",
			Detail: "没有找到：" + strings.Join(missingIn, "、") + "。",
			Advice: "Hysteria2 走 UDP，在 TCP 被墙时仍然能用，三条入口最好都有。修复后会自动把现有线路挂上去。",
			Fix:    "inbounds",
		})
	}
	if len(disabledIn) > 0 {
		d.findings = append(d.findings, Finding{
			ID:     "inbound_off",
			Group:  "VPN 服务",
			Title:  "有入口被关掉了",
			Status: "bad",
			Detail: "面板里这些入口的开关是关着的：" + strings.Join(disabledIn, "、") + "。",
			Fix:    "inbound_enable",
		})
	}
	if len(notListening) > 0 {
		d.findings = append(d.findings, Finding{
			ID:     "listen",
			Group:  "VPN 服务",
			Title:  "入口端口没有在监听",
			Status: "bad",
			Detail: strings.Join(notListening, "、") + " 在面板里是开的，但服务器上没有在监听。",
			Advice: "通常重启 Xray 就好。如果修复后还不行，可能端口被别的程序占用了。",
			Fix:    "restart",
		})
	}
	if len(missingIn) == 0 && len(disabledIn) == 0 && len(notListening) == 0 {
		d.findings = append(d.findings, Finding{
			ID:     "inbounds",
			Group:  "VPN 服务",
			Title:  "三条入口都在正常工作",
			Status: "ok",
			Detail: "Reality（TCP 443）、Hysteria2（UDP 443 和 8443）。",
		})
	}

	if d.env["HY2CERT"] != "yes" {
		d.findings = append(d.findings, Finding{
			ID:     "hy2cert",
			Group:  "VPN 服务",
			Title:  "Hysteria2 证书文件丢失",
			Status: "bad",
			Detail: "/root/cert/hy2 里的证书不见了，Hysteria2 线路无法启动。",
			Fix:    "hy2cert",
		})
	}

	if d.xray != nil {
		blockCN, broken := routingBroken(d.xray)
		modeDesc := "不屏蔽国内（回国模式）"
		if blockCN {
			modeDesc = "翻墙模式（服务器不访问国内网站）"
		}
		if broken {
			d.findings = append(d.findings, Finding{
				ID:     "routing",
				Group:  "VPN 服务",
				Title:  "路由规则不完整或顺序不对",
				Status: "bad",
				Detail: "当前：" + modeDesc + "。规则顺序乱了会让住宅出口失效（显示成 VPS 的 IP）；缺少谷歌例外会让 Google Play 下载一直转圈。",
				Advice: "修复会按标准顺序重新排好：住宅出口规则 → 谷歌例外 → 屏蔽国内。",
				Fix:    "routing",
			})
		} else {
			d.findings = append(d.findings, Finding{
				ID:     "routing",
				Group:  "VPN 服务",
				Title:  "路由规则正常",
				Status: "ok",
				Detail: "当前：" + modeDesc + "。",
			})
		}
	}
}

func (d *doctor) checkExits() {
	if d.panel == nil {
		return
	}
	if len(d.clients) == 0 {
		d.findings = append(d.findings, Finding{
			ID:     "noclient",
			Group:  "线路与住宅出口",
			Title:  "还没有任何线路",
			Status: "bad",
			Detail: "面板里没有客户端，没有人能连上。",
			Advice: "回到首页选「搭建新服务器」重新跑一次，会自动补上。",
		})
		return
	}

	var disabledClients, partialClients []string
	for _, c := range d.clients {
		label := strings.TrimSpace(strings.TrimSuffix(c.Comment, "[CN]"))
		if label == "" {
			label = c.Email
		}
		if !c.Enable {
			disabledClients = append(disabledClients, label)
		}
		if len(c.InboundIDs) < 3 {
			partialClients = append(partialClients, label)
		}
	}
	if len(disabledClients) > 0 {
		d.findings = append(d.findings, Finding{
			ID:     "client_off",
			Group:  "线路与住宅出口",
			Title:  "有线路被停用了",
			Status: "bad",
			Detail: "被停用：" + strings.Join(disabledClients, "、") + "。用这些配置文件的人会连不上。",
			Advice: "停用通常是因为在面板里设置了到期时间或流量上限。修复会重新启用；如果设置了限制，记得在面板里改掉，否则还会再被停用。",
			Fix:    "client_enable",
		})
	}
	if len(partialClients) > 0 {
		d.findings = append(d.findings, Finding{
			ID:     "attach",
			Group:  "线路与住宅出口",
			Title:  "有线路没挂到全部入口上",
			Status: "warn",
			Detail: strings.Join(partialClients, "、") + " 只能用部分入口，配置文件里会少几条备用线路。",
			Fix:    "attach",
		})
	}

	proxyCount := 0
	for _, c := range d.clients {
		if d.xray == nil {
			continue
		}
		outTag := OutboundForUser(d.xray, c.Email)
		if outTag == "" || outTag == "direct" {
			continue
		}
		proxyCount++
		label := strings.TrimSpace(strings.TrimSuffix(c.Comment, "[CN]"))
		if label == "" {
			label = c.Email
		}
		ob := findOutbound(d.xray, outTag)
		if ob == nil {
			d.findings = append(d.findings, Finding{
				ID:     "exit:" + c.Email,
				Group:  "线路与住宅出口",
				Title:  label + "：出口配置丢失",
				Status: "bad",
				Detail: "路由规则指向的出口「" + outTag + "」不存在，Xray 可能因此启动失败。",
				Advice: "修复会删掉这条坏掉的规则，这条线路暂时改为走 VPS 自身的 IP；之后可以在「管理」里重新添加住宅 IP。",
				Fix:    "dangling",
			})
			continue
		}
		rp := proxyOf(ob)
		if rp == nil {
			continue
		}
		if d.log != nil {
			d.log("检测住宅出口：" + label)
		}
		pr := ProbeExit(d.remote, rp)
		if pr.Reachable {
			if pr.Hosting {
				d.findings = append(d.findings, Finding{
					ID:     "exit:" + c.Email,
					Group:  "线路与住宅出口",
					Title:  label + "：能用，但像机房 IP",
					Status: "warn",
					Detail: pr.String(),
					Advice: "一些网站会把机房 IP 当成代理。如果买的是住宅 IP，可以找代理商换一个。",
				})
			} else {
				d.findings = append(d.findings, Finding{
					ID:     "exit:" + c.Email,
					Group:  "线路与住宅出口",
					Title:  label + "：住宅出口正常",
					Status: "ok",
					Detail: pr.String(),
				})
			}
		} else {
			d.findings = append(d.findings, Finding{
				ID:     "exit:" + c.Email,
				Group:  "线路与住宅出口",
				Title:  label + "：住宅出口连不上",
				Status: "bad",
				Detail: fmt.Sprintf("这条线路现在打不开任何网站。常见原因：住宅 IP 到期或流量用完；账号密码被代理商改了；代理商要求把 VPS 的 IP（%s）加进白名单。到代理商后台确认后，在「管理」里删掉这条再重新添加。", d.info.IP),
			})
		}
	}
	if proxyCount == 0 {
		d.findings = append(d.findings, Finding{
			ID:     "exits",
			Group:  "线路与住宅出口",
			Title:  "所有线路都走 VPS 自身的 IP",
			Status: "info",
			Detail: "没有配置住宅出口。需要的话可以在「管理」里添加。",
		})
	}
}

func (d *doctor) checkSecurity() {
	if d.env["FW"] != "yes" {
		d.findings = append(d.findings, Finding{
			ID:     "firewall",
			Group:  "安全防护",
			Title:  "防火墙没有开启",
			Status: "bad",
			Detail: "所有端口都暴露在公网上，容易被扫描和攻击。",
			Advice: "修复会只放行 SSH、面板和 VPN 端口。开启前会先设置 3 分钟自动撤销，确认能重新登录后才保留，不会把你锁在外面。",
			Fix:    "firewall",
		})
	} else {
		fwt := d.env["FWT"]
		allowed := map[string]bool{}
		for _, p := range strings.FieldsFunc(fwt, func(r rune) bool { return r == ',' || r == ' ' }) {
			allowed[p] = true
		}
		var missPorts []string
		for _, need := range []string{d.info.SSHPort, "443"} {
			if need != "" && !allowed[need] {
				missPorts = append(missPorts, need)
			}
		}
		if d.panel != nil && d.panel.Port != "" && !allowed[d.panel.Port] {
			missPorts = append(missPorts, d.panel.Port)
		}
		if len(missPorts) > 0 {
			d.findings = append(d.findings, Finding{
				ID:     "firewall",
				Group:  "安全防护",
				Title:  "防火墙挡住了需要的端口",
				Status: "bad",
				Detail: "这些 TCP 端口没有放行：" + strings.Join(missPorts, "、") + "。可能是改过 SSH 或面板端口。",
				Fix:    "firewall",
			})
		} else {
			d.findings = append(d.findings, Finding{
				ID:     "firewall",
				Group:  "安全防护",
				Title:  "防火墙已开启",
				Status: "ok",
				Detail: "放行 TCP " + fwt + "，UDP 443、8443。",
			})
		}
	}

	f2b := d.env["F2B"] == "active"
	uu := d.env["UU"] == "yes"
	if !f2b || !uu {
		var miss []string
		if !f2b {
			miss = append(miss, "防暴力破解（fail2ban）")
		}
		if !uu {
			miss = append(miss, "自动安全更新")
		}
		d.findings = append(d.findings, Finding{
			ID:     "harden",
			Group:  "安全防护",
			Title:  "安全防护没开全",
			Status: "warn",
			Detail: "没有开启：" + strings.Join(miss, "、") + "。",
			Fix:    "harden",
		})
	} else {
		detail := "已开启防暴力破解和自动安全更新。"
		if banned := d.env["BANNED"]; banned != "" && banned != "0" {
			detail += "目前封禁了 " + banned + " 个尝试破解的 IP。"
		}
		d.findings = append(d.findings, Finding{
			ID:     "harden",
			Group:  "安全防护",
			Title:  "防暴力破解和自动更新正常",
			Status: "ok",
			Detail: detail,
		})
	}

	sshFail := num(d.env["SSHFAIL"])
	if d.env["PWAUTH"] == "yes" {
		d.findings = append(d.findings, Finding{
			ID:     "sshfail",
			Group:  "安全防护",
			Title:  fmt.Sprintf("过去 24 小时有 %d 次 SSH 破解尝试", sshFail),
			Status: "info",
			Detail: "这些都是失败的尝试，不代表被入侵。",
			Advice: "你的服务器允许密码登录。只要 root 密码够长够乱就没事；更安全的做法是改用密钥登录（在商家后台或请懂的朋友帮忙设置）。",
		})
	}

	if d.env["PCERT"] == "yes" {
		sec, _ := strconv.ParseInt(d.env["PCERTSEC"], 10, 64)
		days := float64(sec) / 86400.0
		switch {
		case sec <= 0:
			d.findings = append(d.findings, Finding{
				ID:     "cert",
				Group:  "安全防护",
				Title:  "面板证书已过期",
				Status: "bad",
				Detail: "浏览器打开面板会提示不安全或打不开。VPN 本身不受影响。",
				Fix:    "cert",
			})
		case d.env["ACME"] == "yes" && d.env["FW"] == "yes" && d.env["HOOK"] != "yes":
			d.findings = append(d.findings, Finding{
				ID:     "cert",
				Group:  "安全防护",
				Title:  "面板证书到期后无法自动续期",
				Status: "warn",
				Detail: fmt.Sprintf("证书还剩 %.1f 天。续期需要 80 端口，但防火墙挡住了它，到期后面板会打不开。", days),
				Advice: "修复会设置成续期时临时打开 80 端口，续完马上关上。",
				Fix:    "cert",
			})
		case days <= 3:
			d.findings = append(d.findings, Finding{
				ID:     "cert",
				Group:  "安全防护",
				Title:  "面板证书快到期了",
				Status: "warn",
				Detail: fmt.Sprintf("还剩 %.0f 小时。", float64(sec)/3600.0),
				Fix:    "cert",
			})
		default:
			d.findings = append(d.findings, Finding{
				ID:     "cert",
				Group:  "安全防护",
				Title:  "面板证书正常",
				Status: "ok",
				Detail: fmt.Sprintf("还剩 %.1f 天，会自动续期。", days),
			})
		}
	}
}

func (d *doctor) checkLocal() {
	if d.env["T443"] == "yes" {
		addr := d.info.IP + ":443"
		if strings.Contains(d.info.IP, ":") {
			addr = "[" + d.info.IP + "]:443"
		}
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			_ = conn.Close()
			d.findings = append(d.findings, Finding{
				ID:     "tcp443",
				Group:  "网络连通",
				Title:  "从你的电脑能连上 Reality（TCP 443）",
				Status: "ok",
				Detail: "如果你开着 TUN 模式，这个结果是通过代理测的，仅供参考。",
			})
		} else {
			d.findings = append(d.findings, Finding{
				ID:     "tcp443",
				Group:  "网络连通",
				Title:  "从你的电脑连不上 Reality（TCP 443）",
				Status: "bad",
				Detail: "服务器上 443 端口正常，但你这边连不过去。如果你在国内，多半是这台 VPS 的 IP 被墙了（TCP 被封）。",
				Advice: fmt.Sprintf("在 Clash 里选「Hysteria2」开头的线路，它走 UDP，通常不受影响。可以到 https://www.itdog.cn/tcping/%s:443 看看全国各地能不能连通。如果 UDP 也不行，只能在 VPS 商家后台更换 IP。", d.info.IP),
			})
		}
	}

	if d.panel != nil && len(d.clients) > 0 && d.outDir != "" {
		cfgs := renderConfigs(d.clients, d.inbounds, d.info.IP, d.outDir)
		var outdated []string
		for _, cf := range cfgs {
			if cf.err != nil {
				continue
			}
			b, err := os.ReadFile(cf.basePath + ".yaml")
			if err != nil || string(b) != cf.clashYAML {
				outdated = append(outdated, filepath.Base(cf.basePath+".yaml"))
			}
		}
		if len(outdated) > 0 {
			d.findings = append(d.findings, Finding{
				ID:     "configs",
				Group:  "配置文件",
				Title:  "电脑上的配置文件缺失或过期",
				Status: "warn",
				Detail: "需要更新：" + strings.Join(outdated, "、") + "。",
				Advice: "旧配置文件可能有 DNS 泄露、少了新线路或规则写错。修复后重新导入 Clash Verge，发给朋友的也要换成新的。",
				Fix:    "configs",
			})
		} else {
			d.findings = append(d.findings, Finding{
				ID:     "configs",
				Group:  "配置文件",
				Title:  "配置文件是最新的",
				Status: "ok",
				Detail: "位置：" + d.outDir,
			})
		}
	}
}

func Diagnose(r *Remote, info *ServerInfo, outDir string, log func(string)) ([]Finding, string, error) {
	d := &doctor{
		remote: r,
		info:   info,
		outDir: outDir,
		log:    log,
	}
	if log != nil {
		log("读取服务器状态…")
	}
	if err := d.gather(); err != nil {
		return nil, "", err
	}
	d.checkSystem()
	if log != nil {
		log("检查 VPN 服务…")
	}
	d.checkVPN()
	d.checkExits()
	d.checkSecurity()
	if log != nil {
		log("检查你电脑上的连接和配置文件…")
	}
	d.checkLocal()

	groupOrder := map[string]int{
		"网络连通":    1,
		"VPN 服务":  2,
		"线路与住宅出口": 3,
		"安全防护":    4,
		"服务器状态":   5,
		"配置文件":    6,
	}
	statusOrder := map[string]int{
		"bad":  0,
		"warn": 1,
		"info": 2,
		"ok":   3,
	}
	sort.SliceStable(d.findings, func(i, j int) bool {
		s1, s2 := statusOrder[d.findings[i].Status], statusOrder[d.findings[j].Status]
		if s1 != s2 {
			return s1 < s2
		}
		return groupOrder[d.findings[i].Group] < groupOrder[d.findings[j].Group]
	})

	badCount, warnCount := 0, 0
	for _, f := range d.findings {
		if f.Status == "bad" {
			badCount++
		} else if f.Status == "warn" {
			warnCount++
		}
	}
	summary := fmt.Sprintf("检测完成：%d 个问题，%d 个建议。", badCount, warnCount)
	return d.findings, summary, nil
}

func RunFix(r *Remote, info *ServerInfo, outDir string, fix string, log func(string)) error {
	switch fix {
	case "bbr":
		script := `grep -q 'tcp_congestion_control *= *bbr' /etc/sysctl.conf || printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1 || true
[ "$(sysctl -n net.ipv4.tcp_congestion_control)" = bbr ] || { echo "这台 VPS 的内核不支持 BBR（OpenVZ 架构常见）" >&2; exit 1; }`
		_, err := r.RunStdin("", script)
		return err

	case "ntp":
		script := `apt-get install -y -qq systemd-timesyncd >/dev/null 2>&1 || true
timedatectl set-ntp true
systemctl restart systemd-timesyncd 2>/dev/null || true
sleep 3; timedatectl show -p NTPSynchronized --value`
		_, err := r.RunStdin("", script)
		return err

	case "xui":
		script := `systemctl restart x-ui; for i in $(seq 1 20); do sleep 2; systemctl is-active x-ui >/dev/null && break; done; systemctl is-active x-ui`
		if _, err := r.RunStdin("", script); err != nil {
			return fmt.Errorf("面板重启失败：%v", err)
		}
		return nil

	case "swap":
		script := `if [ "$(awk '/^SwapTotal/{print $2}' /proc/meminfo)" = 0 ]; then
  fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
  chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile || { rm -f /swapfile; echo "这台 VPS 不支持添加虚拟内存" >&2; exit 1; }
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
echo SWAP_OK`
		_, err := r.RunStdin("", script)
		return err

	case "disk":
		script := `apt-get clean
journalctl --vacuum-size=100M >/dev/null 2>&1 || true
find /var/log -type f \( -name '*.gz' -o -name '*.[0-9]' \) -delete 2>/dev/null
rm -f /root/3x-ui-install.sh
df -P / | awk 'NR==2{print "已用 "$5}'`
		_, err := r.RunStdin("", script)
		return err

	case "harden":
		_, _ = r.RunStdin("", "apt-get install -y -qq fail2ban unattended-upgrades >/dev/null")
		return HardenBasics(r, info.SSHPort)

	case "firewall":
		p, err := LoadPanel(r, info.IP)
		if err != nil {
			return err
		}
		_, _ = r.RunStdin("", "command -v nft >/dev/null || apt-get install -y -qq nftables >/dev/null")
		if err := ApplyFirewall(r, info.SSHPort, p.Port); err != nil {
			return err
		}
		_, _ = SetupACMEHooks(r)
		return nil

	case "cert":
		_, _ = SetupACMEHooks(r)
		script := `"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" --force >/dev/null 2>&1 || true
systemctl restart x-ui; sleep 5; systemctl is-active x-ui`
		_, err := r.RunStdin("", script)
		return err

	case "hy2cert":
		return MakeHy2Cert(r)

	case "inbounds":
		p, err := LoadPanel(r, info.IP)
		if err != nil {
			return err
		}
		if err := MakeHy2Cert(r); err != nil {
			return err
		}
		if _, err := EnsureInbounds(p, "www.icloud.com", log); err != nil {
			return err
		}
		return attachAll(p)

	case "inbound_enable":
		p, err := LoadPanel(r, info.IP)
		if err != nil {
			return err
		}
		inbounds, err := p.Inbounds()
		if err != nil {
			return err
		}
		for _, in := range inbounds {
			if !in.Enable {
				if err := p.EnableInbound(in.ID); err != nil {
					return err
				}
				if log != nil {
					log("✓ 已打开 " + in.Remark)
				}
			}
		}
		return nil

	case "attach":
		p, err := LoadPanel(r, info.IP)
		if err != nil {
			return err
		}
		return attachAll(p)

	case "client_enable":
		p, err := LoadPanel(r, info.IP)
		if err != nil {
			return err
		}
		clients, err := p.Clients()
		if err != nil {
			return err
		}
		var emails []string
		for _, c := range clients {
			if !c.Enable {
				emails = append(emails, c.Email)
			}
		}
		if len(emails) > 0 {
			return p.EnableClients(emails)
		}
		return nil

	case "routing":
		p, err := LoadPanel(r, info.IP)
		if err != nil {
			return err
		}
		xray, testURL, err := p.GetXray()
		if err != nil {
			return err
		}
		blockCN, _ := routingBroken(xray)
		EnsureBaseRules(xray, blockCN)
		return p.SaveXray(xray, testURL)

	case "dangling":
		p, err := LoadPanel(r, info.IP)
		if err != nil {
			return err
		}
		xray, testURL, err := p.GetXray()
		if err != nil {
			return err
		}
		clients, _ := p.Clients()
		for _, c := range clients {
			tag := OutboundForUser(xray, c.Email)
			if tag != "" && tag != "direct" && findOutbound(xray, tag) == nil {
				RemoveUserRules(xray, c.Email, "")
				if log != nil {
					log("✓ 已删除 " + strings.TrimSpace(c.Comment) + " 的坏规则")
				}
			}
		}
		return p.SaveXray(xray, testURL)

	case "restart":
		p, err := LoadPanel(r, info.IP)
		if err != nil {
			return err
		}
		return p.RestartXray()

	case "configs":
		p, err := LoadPanel(r, info.IP)
		if err != nil {
			return err
		}
		writePanelInfo(outDir, p, info)
		_, err = exportAll(p, info.IP, outDir, nil, log)
		return err
	}
	return fmt.Errorf("未知的修复项：%s", fix)
}

func attachAll(p *Panel) error {
	inbounds, err := p.Inbounds()
	if err != nil {
		return err
	}
	clients, err := p.Clients()
	if err != nil {
		return err
	}
	var ids []int
	for _, in := range inbounds {
		if (in.Protocol == "vless" && in.Port == 443) || (in.Protocol == "hysteria" && (in.Port == 443 || in.Port == 8443)) {
			ids = append(ids, in.ID)
		}
	}
	for _, c := range clients {
		if len(c.InboundIDs) < len(ids) {
			if err := p.AttachClient(c.Email, ids); err != nil {
				return err
			}
		}
	}
	return nil
}

func QuickCheck(host, sshPort string) (sshOK, tlsOK bool) {
	probe := func(addr string) bool {
		c, err := net.DialTimeout("tcp", addr, 3500*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
	joinAddr := func(p string) string {
		if strings.Contains(host, ":") {
			return "[" + host + "]:" + p
		}
		return host + ":" + p
	}
	ch := make(chan bool, 1)
	go func() {
		ch <- probe(joinAddr("443"))
	}()
	sshOK = probe(joinAddr(sshPort))
	tlsOK = <-ch
	return sshOK, tlsOK
}

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type ResProxy struct {
	Protocol string
	Host     string
	Port     int
	User     string
	Pass     string
}

type ExitSpec struct {
	Email string
	Label string
	China bool
	Proxy *ResProxy
}

type ProbeResult struct {
	Reachable bool
	IP        string
	Country   string
	City      string
	Org       string
	Hosting   bool
	Err       string
}

var (
	reTagName  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	reHosting  = regexp.MustCompile(`(?i)hosting|cloud|data ?cent|server|vps|colo|akile|it7|xtom|digitalocean|vultr|linode|akamai|ovh|hetzner|amazon|aws|google|microsoft|azure|oracle|alibaba|tencent|choopa|leaseweb|m247|cogent|psychz|dmit|bandwagon|contabo|ionos|scaleway|zenlayer|gcore|cdn77|datacamp`)
	reIPv4     = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
	protoLabel = map[string]string{
		"socks":       "SOCKS5",
		"http":        "HTTP",
		"shadowsocks": "Shadowsocks",
		"vless":       "VLESS",
		"vmess":       "VMess",
		"trojan":      "Trojan",
		"wireguard":   "WireGuard",
		"hysteria":    "Hysteria2",
	}
)

func ParseProxyLine(line string) (*ResProxy, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("代理地址为空")
	}
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil {
			return nil, fmt.Errorf("代理格式无法识别：%v", err)
		}
		scheme := strings.ToLower(u.Scheme)
		proto := "socks"
		switch scheme {
		case "socks5", "socks5h", "socks":
			proto = "socks"
		case "http", "https":
			proto = "http"
		default:
			return nil, fmt.Errorf("不支持 %s 协议（只支持 SOCKS5 和 HTTP）", u.Scheme)
		}
		host, portStr, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, fmt.Errorf("代理地址缺少端口号")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("端口号不正确")
		}
		var user, pass string
		if u.User != nil {
			user = u.User.Username()
			pass, _ = u.User.Password()
		}
		return &ResProxy{
			Protocol: proto,
			Host:     host,
			Port:     port,
			User:     user,
			Pass:     pass,
		}, nil
	}

	parts := strings.Split(line, ":")
	if len(parts) != 2 && len(parts) != 4 {
		return nil, fmt.Errorf("格式不对，应为 主机:端口:账号:密码 或 socks5://账号:密码@主机:端口")
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("端口号不正确")
	}
	rp := &ResProxy{
		Protocol: "socks",
		Host:     parts[0],
		Port:     port,
	}
	if len(parts) == 4 {
		rp.User = parts[2]
		rp.Pass = parts[3]
	}
	return rp, nil
}

func curlCfgQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func ProbeExit(r *Remote, rp *ResProxy) ProbeResult {
	scheme := "socks5h"
	if rp.Protocol == "http" {
		scheme = "http"
	}
	cfg := fmt.Sprintf("proxy = %s\n", curlCfgQuote(fmt.Sprintf("%s://%s:%d", scheme, rp.Host, rp.Port)))
	if rp.User != "" || rp.Pass != "" {
		cfg += fmt.Sprintf("proxy-user = %s\n", curlCfgQuote(rp.User+":"+rp.Pass))
	}
	script := `
CFGF=$(mktemp); chmod 600 "$CFGF"
printf '%s' "$DATA" > "$CFGF"
OUT=$(curl -4 -sS -m 15 -K "$CFGF" https://ipinfo.io/json 2>&1)
rc=$?
if [ $rc -eq 0 ] && echo "$OUT" | grep -q '"ip"'; then
  echo "IPINFO $OUT"
else
  OUT2=$(curl -4 -sS -m 15 -K "$CFGF" https://myip.ipip.net 2>&1)
  rc2=$?
  if [ $rc2 -eq 0 ] && [ -n "$OUT2" ]; then
    echo "IPIP $OUT2"
  else
    echo "FAIL $OUT"
  fi
fi
rm -f "$CFGF"`
	out, err := r.RunStdin(cfg, script)
	if err != nil {
		return ProbeResult{Err: err.Error()}
	}
	out = strings.TrimSpace(out)
	if strings.HasPrefix(out, "IPINFO ") {
		raw := strings.TrimPrefix(out, "IPINFO ")
		var m map[string]any
		_ = json.Unmarshal([]byte(raw), &m)
		res := ProbeResult{
			Reachable: true,
			IP:        getStr(m, "ip"),
			Country:   getStr(m, "country"),
			City:      strings.TrimSpace(getStr(m, "region") + " " + getStr(m, "city")),
			Org:       getStr(m, "org"),
		}
		res.Hosting = reHosting.MatchString(res.Org)
		return res
	}
	if strings.HasPrefix(out, "IPIP ") {
		raw := strings.TrimPrefix(out, "IPIP ")
		ip := reIPv4.FindString(raw)
		cc := ""
		if strings.Contains(raw, "中国") {
			cc = "CN"
		}
		res := ProbeResult{
			Reachable: true,
			IP:        ip,
			Country:   cc,
			Org:       raw,
			Hosting:   reHosting.MatchString(raw) || strings.Contains(raw, "数据中心") || strings.Contains(raw, "云"),
		}
		return res
	}
	return ProbeResult{
		Err: strings.TrimSpace(strings.TrimPrefix(out, "FAIL ")),
	}
}

func (pr ProbeResult) String() string {
	if !pr.Reachable {
		return "连接失败：" + pr.Err
	}
	kind := "住宅/ISP"
	if pr.Hosting {
		kind = "数据中心/机房"
	}
	loc := strings.TrimSpace(strings.Join([]string{pr.Country, pr.City}, " "))
	return fmt.Sprintf("出口 IP %s｜%s｜%s｜%s", pr.IP, loc, pr.Org, kind)
}

func flagFor(cc string) string {
	f := flagEmoji(strings.TrimSpace(cc))
	if f == "" {
		return ""
	}
	return f + " "
}

func AddExit(p *Panel, spec ExitSpec, inboundIDs []int) error {
	xray, testURL, err := p.GetXray()
	if err != nil {
		return err
	}
	outTag := spec.Email + "-O"
	if findOutbound(xray, outTag) != nil {
		return fmt.Errorf("出站 %s 已存在", outTag)
	}

	srv := map[string]any{
		"address": spec.Proxy.Host,
		"port":    spec.Proxy.Port,
	}
	if spec.Proxy.User != "" || spec.Proxy.Pass != "" {
		srv["users"] = []any{
			map[string]any{
				"user": spec.Proxy.User,
				"pass": spec.Proxy.Pass,
			},
		}
	}
	ob := map[string]any{
		"tag":      outTag,
		"protocol": spec.Proxy.Protocol,
		"settings": map[string]any{
			"servers": []any{srv},
		},
	}
	obs, _ := xray["outbounds"].([]any)
	xray["outbounds"] = append(obs, ob)

	routing, _ := xray["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
	}
	rules, _ := routing["rules"].([]any)
	userRule := map[string]any{
		"type":        "field",
		"user":        []string{spec.Email},
		"outboundTag": outTag,
	}
	routing["rules"] = InsertUserRule(rules, userRule)
	xray["routing"] = routing

	if err := p.SaveXray(xray, testURL); err != nil {
		return err
	}
	comment := spec.Label
	if spec.China {
		comment += " [CN]"
	}
	if err := p.AddClient(spec.Email, comment, "xtls-rprx-vision", inboundIDs); err != nil {
		if x2, t2, e2 := p.GetXray(); e2 == nil {
			RemoveUserRules(x2, spec.Email, outTag)
			_ = p.SaveXray(x2, t2)
		}
		return err
	}
	return nil
}

func RemoveExit(p *Panel, email string) error {
	if err := p.DelClient(email); err != nil {
		return err
	}
	xray, testURL, err := p.GetXray()
	if err != nil {
		return err
	}
	RemoveUserRules(xray, email, email+"-O")
	return p.SaveXray(xray, testURL)
}

func NextExitName(clients []PClient, xray map[string]any) string {
	used := map[string]bool{}
	for _, c := range clients {
		used[c.Email] = true
	}
	if obs, ok := xray["outbounds"].([]any); ok {
		for _, item := range obs {
			if om, ok := item.(map[string]any); ok {
				used[getStr(om, "tag")] = true
			}
		}
	}
	for i := 1; ; i++ {
		name := fmt.Sprintf("ISP-%d", i)
		if !used[name] && !used[name+"-O"] {
			return name
		}
	}
}

func outboundAddr(ob map[string]any) string {
	set := asObj(ob["settings"])
	joinHostPort := func(m map[string]any) string {
		addr := getStr(m, "address")
		port := getStr(m, "port")
		if port == "" {
			if pv, ok := m["port"]; ok {
				port = fmt.Sprint(pv)
			}
		}
		if addr == "" {
			return ""
		}
		if strings.Contains(addr, ":") {
			return "[" + addr + "]:" + port
		}
		return addr + ":" + port
	}
	if srvs, ok := set["servers"].([]any); ok && len(srvs) > 0 {
		return joinHostPort(asObj(srvs[0]))
	}
	if vnext, ok := set["vnext"].([]any); ok && len(vnext) > 0 {
		return joinHostPort(asObj(vnext[0]))
	}
	if peers, ok := set["peers"].([]any); ok && len(peers) > 0 {
		return getStr(asObj(peers[0]), "endpoint")
	}
	return joinHostPort(set)
}

func isProxyOutbound(ob map[string]any) bool {
	proto := getStr(ob, "protocol")
	if _, ok := protoLabel[proto]; ok {
		return true
	}
	return outboundAddr(ob) != ""
}

func strList(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		var out []string
		for _, item := range x {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		var out []string
		for _, part := range strings.Split(x, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}

func ExitOf(xray map[string]any, c PClient, inbounds []Inbound) string {
	inTags := map[string]bool{}
	allowed := map[int]bool{}
	for _, id := range c.InboundIDs {
		allowed[id] = true
	}
	for _, in := range inbounds {
		if len(allowed) == 0 || allowed[in.ID] {
			if in.Tag != "" {
				inTags[in.Tag] = true
			}
		}
	}
	routing, _ := xray["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	for _, item := range rules {
		rm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		users := strList(rm["user"])
		if len(users) > 0 {
			for _, u := range users {
				if u == c.Email {
					if bt := getStr(rm, "balancerTag"); bt != "" {
						return "balancer:" + bt
					}
					return getStr(rm, "outboundTag")
				}
			}
			continue
		}
		ibTags := strList(rm["inboundTag"])
		for _, t := range ibTags {
			if inTags[t] {
				if bt := getStr(rm, "balancerTag"); bt != "" {
					return "balancer:" + bt
				}
				return getStr(rm, "outboundTag")
			}
		}
	}
	return "direct"
}

func DescribeExit(xray map[string]any, c PClient, inbounds []Inbound) (where, kind string) {
	tag := ExitOf(xray, c, inbounds)
	if strings.HasPrefix(tag, "balancer:") {
		return "负载均衡「" + strings.TrimPrefix(tag, "balancer:") + "」（多个出口轮流用）", "balancer"
	}
	if tag == "blocked" {
		return "被屏蔽（规则指向 blackhole）", "blocked"
	}
	if tag == "" || tag == "direct" {
		return "VPS 本机 IP（直连）", "direct"
	}
	ob := findOutbound(xray, tag)
	if ob == nil {
		return "出站「" + tag + "」不存在（规则写错了，流量会走不通）", "missing"
	}
	proto := getStr(ob, "protocol")
	if proto == "freedom" {
		return "VPS 本机 IP（直连）", "direct"
	}
	if proto == "blackhole" {
		return "被屏蔽（规则指向 blackhole）", "blocked"
	}
	pLabel := protoLabel[proto]
	if pLabel == "" {
		pLabel = proto
	}
	return strings.TrimSpace(pLabel + " " + outboundAddr(ob)), "proxy"
}

func IdleOutbounds(xray map[string]any) []map[string]string {
	used := map[string]bool{}
	routing, _ := xray["routing"].(map[string]any)
	if rules, ok := routing["rules"].([]any); ok {
		for _, item := range rules {
			if rm, ok := item.(map[string]any); ok {
				if t := getStr(rm, "outboundTag"); t != "" {
					used[t] = true
				}
			}
		}
	}
	if bals, ok := routing["balancers"].([]any); ok {
		for _, item := range bals {
			if bm, ok := item.(map[string]any); ok {
				for _, s := range strList(bm["selector"]) {
					used[s] = true
				}
			}
		}
	}
	obs, _ := xray["outbounds"].([]any)
	var idle []map[string]string
	for _, item := range obs {
		om, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag := getStr(om, "tag")
		if tag == "" || used[tag] || !isProxyOutbound(om) {
			continue
		}
		proto := getStr(om, "protocol")
		pLabel := protoLabel[proto]
		if pLabel == "" {
			pLabel = proto
		}
		idle = append(idle, map[string]string{
			"tag":   tag,
			"where": strings.TrimSpace(pLabel + " " + outboundAddr(om)),
		})
	}
	return idle
}

func AdoptOutbound(p *Panel, outboundTag, email, label string, china bool, inboundIDs []int) error {
	xray, testURL, err := p.GetXray()
	if err != nil {
		return err
	}
	ob := findOutbound(xray, outboundTag)
	if ob == nil || !isProxyOutbound(ob) {
		return fmt.Errorf("面板里没有叫「%s」的代理出站", outboundTag)
	}
	routing, _ := xray["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
	}
	rules, _ := routing["rules"].([]any)
	userRule := map[string]any{
		"type":        "field",
		"user":        []string{email},
		"outboundTag": outboundTag,
	}
	routing["rules"] = InsertUserRule(rules, userRule)
	xray["routing"] = routing
	if err := p.SaveXray(xray, testURL); err != nil {
		return err
	}
	comment := label
	if china {
		comment += " [CN]"
	}
	if err := p.AddClient(email, comment, "xtls-rprx-vision", inboundIDs); err != nil {
		return err
	}
	return nil
}

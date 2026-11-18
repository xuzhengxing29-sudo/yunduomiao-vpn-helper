package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

type lineInfo struct {
	Name  string
	Clash string
	URI   string
}

const (
	clashHeader = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
# IPv6 交给虚拟网卡接住，再由规则第一条全部拒绝：既不用 IPv6，也不会从旁路漏出去
ipv6: true
unified-delay: true
tcp-concurrent: true
geodata-mode: true
geox-url:
  geoip: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  mmdb: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"

sniffer:
  enable: true
  sniff:
    HTTP: {ports: [80, 8080-8880], override-destination: true}
    TLS: {ports: [443, 8443]}
    QUIC: {ports: [443, 8443]}

# 虚拟网卡模式：所有程序的流量和 DNS 查询都进 VPN，浏览器的 WebRTC 也只能看到出口 IP
tun:
  enable: true
  stack: mixed
  auto-route: true
  strict-route: true
  auto-detect-interface: true
  dns-hijack: ["any:53", "tcp://any:53"]
`

	clashDNS = `
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: ['*.lan', '+.local', '+.msftconnecttest.com', '+.msftncsi.com', 'time.*.com', 'ntp.*.com']
  respect-rules: true
  default-nameserver: [1.1.1.1, 8.8.8.8]
  proxy-server-nameserver: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']
  nameserver: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']
  nameserver-policy:
    'geosite:cn': ['https://223.5.5.5/dns-query', 'https://doh.pub/dns-query']
`

	clashDNSChina = `
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: ['*.lan', '+.local']
  respect-rules: true
  default-nameserver: [223.5.5.5, 1.1.1.1]
  proxy-server-nameserver: ['https://1.1.1.1/dns-query']
  nameserver: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']
  nameserver-policy:
    'geosite:cn': ['https://223.5.5.5/dns-query', 'https://doh.pub/dns-query']
`

	clashRules = `
rules:
  - IP-CIDR6,::/0,REJECT,no-resolve
  - DOMAIN-SUFFIX,googleapis.cn,PROXY
  - DOMAIN-SUFFIX,xn--ngstr-lra8j.com,PROXY
  - DOMAIN-SUFFIX,gvt1.com,PROXY
  - DOMAIN-SUFFIX,gvt2.com,PROXY
  - DOMAIN,dl.google.com,PROXY
  - GEOSITE,google,PROXY
  - GEOSITE,private,DIRECT
  - GEOSITE,cn,DIRECT
  - GEOIP,LAN,DIRECT,no-resolve
  - GEOIP,CN,DIRECT,no-resolve
  - MATCH,PROXY
`

	clashRulesChina = `
rules:
  - IP-CIDR6,::/0,REJECT,no-resolve
  - GEOSITE,private,DIRECT
  - GEOIP,LAN,DIRECT,no-resolve
  - GEOSITE,cn,PROXY
  - GEOIP,CN,PROXY,no-resolve
  - MATCH,DIRECT
`
)

func stripFlag(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func BuildLines(c PClient, inbounds []Inbound, serverIP, label string) []lineInfo {
	allowed := map[int]bool{}
	for _, id := range c.InboundIDs {
		allowed[id] = true
	}

	var hy8443, hy443, reality []lineInfo
	for _, in := range inbounds {
		if !in.Enable || (len(allowed) > 0 && !allowed[in.ID]) {
			continue
		}
		stream := asObj(in.Stream)
		sec := getStr(stream, "security")
		netType := getStr(stream, "network")

		if in.Protocol == "hysteria" || netType == "hysteria" {
			tlsObj := asObj(stream["tlsSettings"])
			sni := getStr(tlsObj, "serverName")
			if sni == "" {
				sni = "www.bing.com"
			}
			alpn := strList(tlsObj["alpn"])
			if len(alpn) == 0 {
				alpn = []string{"h3"}
			}
			var obfsType, obfsPass string
			fm := asObj(stream["finalmask"])
			if udpList, ok := fm["udp"].([]any); ok && len(udpList) > 0 {
				u0 := asObj(udpList[0])
				obfsType = getStr(u0, "type")
				obfsPass = getStr(asObj(u0["settings"]), "password")
			}

			name := fmt.Sprintf("%s-Hy2-%d", label, in.Port)
			nameJSON, _ := json.Marshal(name)
			passJSON, _ := json.Marshal(c.Password)
			var yb strings.Builder
			fmt.Fprintf(&yb, "  - name: %s\n    type: hysteria2\n    server: %s\n    port: %d\n    password: %s\n",
				string(nameJSON), serverIP, in.Port, string(passJSON))
			if obfsType == "salamander" && obfsPass != "" {
				opJSON, _ := json.Marshal(obfsPass)
				fmt.Fprintf(&yb, "    obfs: salamander\n    obfs-password: %s\n", string(opJSON))
			}
			var alpnJSONs []string
			for _, a := range alpn {
				aj, _ := json.Marshal(a)
				alpnJSONs = append(alpnJSONs, string(aj))
			}
			sniJSON, _ := json.Marshal(sni)
			fmt.Fprintf(&yb, "    sni: %s\n    alpn: [%s]\n    skip-cert-verify: true",
				string(sniJSON), strings.Join(alpnJSONs, ", "))

			q := url.Values{}
			q.Set("insecure", "1")
			q.Set("sni", sni)
			q.Set("alpn", strings.Join(alpn, ","))
			if obfsType == "salamander" && obfsPass != "" {
				q.Set("obfs", "salamander")
				q.Set("obfs-password", obfsPass)
			}
			uri := fmt.Sprintf("hysteria2://%s@%s:%d/?%s#%s",
				url.PathEscape(c.Password), serverIP, in.Port, q.Encode(), url.PathEscape(name))

			li := lineInfo{Name: name, Clash: yb.String(), URI: uri}
			if in.Port == 8443 {
				hy8443 = append(hy8443, li)
			} else {
				hy443 = append(hy443, li)
			}
		} else if in.Protocol == "vless" && sec == "reality" {
			realObj := asObj(stream["realitySettings"])
			realSet := asObj(realObj["settings"])
			pbk := getStr(realSet, "publicKey")
			fp := getStr(realSet, "fingerprint")
			if fp == "" {
				fp = "chrome"
			}
			snames := strList(realObj["serverNames"])
			sni := "www.bing.com"
			if len(snames) > 0 && snames[0] != "" {
				sni = snames[0]
			}
			sids := strList(realObj["shortIds"])
			sid := ""
			for _, s := range sids {
				if s != "" {
					sid = s
					break
				}
			}

			name := fmt.Sprintf("%s-Reality-%d", label, in.Port)
			nameJSON, _ := json.Marshal(name)
			uuidJSON, _ := json.Marshal(c.ID)
			var yb strings.Builder
			fmt.Fprintf(&yb, "  - name: %s\n    type: vless\n    server: %s\n    port: %d\n    uuid: %s\n    network: tcp\n    tls: true\n    udp: true\n",
				string(nameJSON), serverIP, in.Port, string(uuidJSON))
			if c.Flow != "" {
				fmt.Fprintf(&yb, "    flow: %s\n", c.Flow)
			}
			sniJSON, _ := json.Marshal(sni)
			fpJSON, _ := json.Marshal(fp)
			pbkJSON, _ := json.Marshal(pbk)
			sidJSON, _ := json.Marshal(sid)
			fmt.Fprintf(&yb, "    servername: %s\n    client-fingerprint: %s\n    reality-opts:\n      public-key: %s\n      short-id: %s",
				string(sniJSON), string(fpJSON), string(pbkJSON), string(sidJSON))

			q := url.Values{}
			q.Set("encryption", "none")
			q.Set("security", "reality")
			q.Set("type", "tcp")
			q.Set("sni", sni)
			q.Set("fp", fp)
			q.Set("pbk", pbk)
			q.Set("sid", sid)
			if c.Flow != "" {
				q.Set("flow", c.Flow)
			}
			uri := fmt.Sprintf("vless://%s@%s:%d?%s#%s",
				c.ID, serverIP, in.Port, q.Encode(), url.PathEscape(name))

			reality = append(reality, lineInfo{Name: name, Clash: yb.String(), URI: uri})
		}
	}

	out := append([]lineInfo{}, hy8443...)
	out = append(out, hy443...)
	out = append(out, reality...)
	return out
}

type exitGroup struct {
	Label string
	Lines []lineInfo
}

func BuildClash(label string, lines []lineInfo, china bool) string {
	return BuildClashMulti([]exitGroup{{Label: label, Lines: lines}}, china)
}

func BuildClashMulti(groups []exitGroup, china bool) string {
	testURL := "https://www.gstatic.com/generate_204"
	modeDesc := "模式：翻墙（国内直连，国外走代理）"
	if china {
		testURL = "https://www.baidu.com"
		modeDesc = "模式：回国（国内网站走中国住宅 IP，其它直连）"
	}

	usedNames := map[string]bool{
		"PROXY":  true,
		"DIRECT": true,
		"REJECT": true,
	}
	var (
		headerComments []string
		proxyBlocks    []string
		groupNames     []string
		fallbackBlocks strings.Builder
	)

	for _, g := range groups {
		gName := g.Label
		for idx := 2; usedNames[gName]; idx++ {
			gName = fmt.Sprintf("%s %d", g.Label, idx)
		}
		usedNames[gName] = true
		gNameJSON, _ := json.Marshal(gName)
		groupNames = append(groupNames, string(gNameJSON))

		var lineNames []string
		var lineJSONs []string
		for _, li := range g.Lines {
			lineNames = append(lineNames, li.Name)
			lj, _ := json.Marshal(li.Name)
			lineJSONs = append(lineJSONs, string(lj))
			proxyBlocks = append(proxyBlocks, li.Clash)
		}
		headerComments = append(headerComments, fmt.Sprintf("#   %s：%s", gName, strings.Join(lineNames, " → ")))
		fmt.Fprintf(&fallbackBlocks, "  - name: %s\n    type: fallback\n    proxies: [%s]\n    url: %s\n    interval: 120\n    timeout: 3000\n    max-failed-times: 2\n    lazy: false\n",
			string(gNameJSON), strings.Join(lineJSONs, ", "), testURL)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# 生成时间：%s\n# %s\n# 共 %d 个出口，在客户端的 PROXY 分组里点选；每个出口内的线路按顺序自动切换：\n%s\n",
		time.Now().Format("2006-01-02 15:04"), modeDesc, len(groups), strings.Join(headerComments, "\n"))
	b.WriteString(clashHeader)
	if china {
		b.WriteString(clashDNSChina)
	} else {
		b.WriteString(clashDNS)
	}
	b.WriteString("\nproxies:\n")
	b.WriteString(strings.Join(proxyBlocks, "\n"))
	fmt.Fprintf(&b, "\n\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [%s, DIRECT]\n", strings.Join(groupNames, ", "))
	b.WriteString(fallbackBlocks.String())
	if china {
		b.WriteString(clashRulesChina)
	} else {
		b.WriteString(clashRules)
	}
	_ = utf8.RuneCountInString
	return b.String()
}

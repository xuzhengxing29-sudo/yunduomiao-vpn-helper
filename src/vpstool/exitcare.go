package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ExitProblem struct {
	Code    string `json:"code"`
	Text    string `json:"text"`
	Advice  string `json:"advice,omitempty"`
	Fixable bool   `json:"fixable"`
	Bad     bool   `json:"bad"`
}

type ExitHealth struct {
	Email    string        `json:"email"`
	Label    string        `json:"label"`
	Status   string        `json:"status"`
	Problems []ExitProblem `json:"problems"`
	Detail   string        `json:"detail,omitempty"`
	At       int64         `json:"at"`
}

func proxyOf(ob map[string]any) *ResProxy {
	if ob == nil {
		return nil
	}
	proto := getStr(ob, "protocol")
	if proto != "socks" && proto != "http" {
		return nil
	}
	set := asObj(ob["settings"])
	srvs, ok := set["servers"].([]any)
	if !ok || len(srvs) == 0 {
		return nil
	}
	s0 := asObj(srvs[0])
	portStr := getStr(s0, "port")
	if portStr == "" {
		if pv, ok := s0["port"]; ok {
			portStr = fmt.Sprint(pv)
		}
	}
	port, _ := strconv.Atoi(portStr)
	host := getStr(s0, "address")
	if host == "" || port <= 0 {
		return nil
	}
	rp := &ResProxy{
		Protocol: proto,
		Host:     host,
		Port:     port,
	}
	if users, ok := s0["users"].([]any); ok && len(users) > 0 {
		u0 := asObj(users[0])
		rp.User = getStr(u0, "user")
		rp.Pass = getStr(u0, "pass")
	} else {
		rp.User = getStr(s0, "user")
		rp.Pass = getStr(s0, "pass")
	}
	return rp
}

func whyProxyFails(errText, serverIP string) (title, advice string) {
	low := strings.ToLower(errText)
	switch {
	case hasAny(low, "407", "authentication", "auth", "unauthorized", "password"):
		return "账号或密码不对，或者住宅 IP 已经到期",
			"到代理商后台核对账号密码和到期时间；如果后台要求 IP 白名单，把 VPS 的 IP（" + serverIP + "）加进去。改好后在这里删掉这条线路重新添加。"
	case hasAny(low, "could not resolve", "resolve host"):
		return "代理的域名解析不出来",
			"代理商给的地址可能换了或者写错了。到代理商后台复制最新的地址，删掉这条线路重新添加。"
	case hasAny(low, "connection refused"):
		return "代理服务器拒绝连接（端口不对，或者这个 IP 已经下线）",
			"到代理商后台确认端口和状态；到期或被回收的住宅 IP 需要续费或换一个。"
	case hasAny(low, "timed out", "timeout"):
		return "代理服务器没有回应",
			"常见原因：住宅 IP 到期或流量用完；代理商要求把 VPS 的 IP（" + serverIP + "）加进白名单；代理商那边临时故障。到代理商后台确认。"
	case hasAny(low, "empty reply", "reset by peer", "connection closed", "eof"):
		return "连上了代理，但它把连接掐断了",
			"多半是没加白名单或套餐流量用完。到代理商后台确认，并把 VPS 的 IP（" + serverIP + "）加进白名单。"
	default:
		return "通过它打不开任何网站",
			"到代理商后台确认这个住宅 IP 还在有效期、流量没用完、VPS 的 IP（" + serverIP + "）在白名单里。"
	}
}

func userRuleAfterBlock(xray map[string]any, email string) bool {
	routing, _ := xray["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	seenBlock := false
	for _, item := range rules {
		rm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if isCNBlockRule(rm) {
			seenBlock = true
		}
		for _, u := range strList(rm["user"]) {
			if u == email {
				return seenBlock
			}
		}
	}
	return false
}

func CheckExitHealth(r *Remote, p *Panel, serverIP string, log func(string)) ([]ExitHealth, error) {
	clients, err := p.Clients()
	if err != nil {
		return nil, err
	}
	inbounds, err := p.Inbounds()
	if err != nil {
		return nil, err
	}
	xray, _, err := p.GetXray()
	if err != nil {
		return nil, err
	}

	var results []ExitHealth
	nowSec := time.Now().Unix()
	nowMs := time.Now().UnixMilli()

	for _, c := range clients {
		label := strings.TrimSpace(strings.TrimSuffix(c.Comment, "[CN]"))
		if label == "" {
			label = c.Email
		}
		eh := ExitHealth{
			Email:    c.Email,
			Label:    label,
			Status:   "ok",
			Problems: []ExitProblem{},
			At:       nowSec,
		}

		if !c.Enable {
			if c.ExpiryTime > 0 && c.ExpiryTime < nowMs {
				eh.Problems = append(eh.Problems, ExitProblem{
					Code:   "expired",
					Text:   "这条线路设置的到期日已经过了，被自动停用",
					Advice: "点这条线路的「设置」，把到期日往后改或清空，它会重新启用。",
					Bad:    true,
				})
			} else if c.TotalGB > 0 && c.Up+c.Down >= c.TotalGB {
				eh.Problems = append(eh.Problems, ExitProblem{
					Code:   "quota",
					Text:   "这条线路设置的流量上限用完了，被自动停用",
					Advice: "点这条线路的「设置」，调大流量上限，或者点「流量清零」。",
					Bad:    true,
				})
			} else {
				eh.Problems = append(eh.Problems, ExitProblem{
					Code:    "off",
					Text:    "线路被停用了，用它的人连不上",
					Fixable: true,
					Bad:     true,
				})
			}
		}

		lines := BuildLines(c, inbounds, "0.0.0.0", label)
		if len(lines) < 3 {
			eh.Problems = append(eh.Problems, ExitProblem{
				Code:    "attach",
				Text:    fmt.Sprintf("没有挂到全部入口上（少 %d 个），配置文件里会缺线路", 3-len(lines)),
				Fixable: true,
				Bad:     len(lines) == 0,
			})
		}

		where, kind := DescribeExit(xray, c, inbounds)
		if userRuleAfterBlock(xray, c.Email) {
			eh.Problems = append(eh.Problems, ExitProblem{
				Code:    "order",
				Text:    "路由规则的顺序不对：它排在「屏蔽国内」后面，一部分网站会打不开",
				Fixable: true,
				Bad:     true,
			})
		}

		switch kind {
		case "blocked":
			eh.Problems = append(eh.Problems, ExitProblem{
				Code:   "blocked",
				Text:   "规则把这条线路指向了「屏蔽」，所有流量都被丢掉",
				Advice: "这是在面板里手动设置的。到 3x-ui 的路由规则里把这条规则的出站改成要用的住宅出口。",
				Bad:    true,
			})
		case "missing":
			outTag := ExitOf(xray, c, inbounds)
			eh.Problems = append(eh.Problems, ExitProblem{
				Code:    "missing",
				Text:    "规则指向的出站「" + outTag + "」已经不存在了，流量走不通",
				Fixable: true,
				Bad:     true,
			})
		case "proxy":
			outTag := ExitOf(xray, c, inbounds)
			ob := findOutbound(xray, outTag)
			rp := proxyOf(ob)
			if rp != nil {
				if log != nil {
					log("检测 " + label + " …")
				}
				pr := ProbeExit(r, rp)
				if pr.Reachable {
					eh.Detail = pr.String()
					if pr.Hosting {
						eh.Problems = append(eh.Problems, ExitProblem{
							Code:   "hosting",
							Text:   "能用，但看起来是机房 IP，不是住宅 IP",
							Advice: "有些网站会把机房 IP 当成代理。如果买的是住宅 IP，可以找代理商换一个。",
							Bad:    false,
						})
					}
				} else {
					altProto := "http"
					if rp.Protocol == "http" {
						altProto = "socks"
					}
					altCopy := *rp
					altCopy.Protocol = altProto
					altRes := ProbeExit(r, &altCopy)
					if altRes.Reachable {
						pNames := map[string]string{"socks": "SOCKS5", "http": "HTTP"}
						eh.Problems = append(eh.Problems, ExitProblem{
							Code:    "proto",
							Text:    fmt.Sprintf("协议选错了：面板里填的是 %s，但这个住宅 IP 实际要用 %s 才能连上", pNames[rp.Protocol], pNames[altProto]),
							Fixable: true,
							Bad:     true,
						})
					} else {
						t, adv := whyProxyFails(pr.Err, serverIP)
						eh.Problems = append(eh.Problems, ExitProblem{
							Code:   "dead",
							Text:   "住宅 IP 连不上：" + t,
							Advice: adv,
							Bad:    true,
						})
					}
				}
			} else {
				eh.Detail = "出口 " + where + "（这种协议没法自动检测，需要自己连上试一下）"
			}
		default:
			eh.Detail = where
		}

		logSummary := eh.Detail
		if logSummary == "" {
			logSummary = "正常"
		}
		if len(eh.Problems) > 0 {
			var texts []string
			hasBad := false
			for _, prob := range eh.Problems {
				texts = append(texts, prob.Text)
				if prob.Bad {
					hasBad = true
				}
			}
			if hasBad {
				eh.Status = "bad"
			} else {
				eh.Status = "warn"
			}
			logSummary = strings.Join(texts, "；")
		}
		if log != nil {
			icons := map[string]string{"ok": "✓", "warn": "⚠", "bad": "✗"}
			log(fmt.Sprintf("%s %s：%s", icons[eh.Status], eh.Label, logSummary))
		}
		results = append(results, eh)
	}
	return results, nil
}

func RepairExits(p *Panel, healths []ExitHealth, log func(string)) error {
	xray, testURL, err := p.GetXray()
	if err != nil {
		return err
	}
	inbounds, err := p.Inbounds()
	if err != nil {
		return err
	}
	var allInboundIDs []int
	for _, in := range inbounds {
		if (in.Protocol == "vless" && in.Port == 443) || (in.Protocol == "hysteria" && (in.Port == 443 || in.Port == 8443)) {
			allInboundIDs = append(allInboundIDs, in.ID)
		}
	}

	xrayDirty := false
	var toEnable []string

	for _, eh := range healths {
		for _, prob := range eh.Problems {
			if !prob.Fixable {
				continue
			}
			switch prob.Code {
			case "off":
				toEnable = append(toEnable, eh.Email)
				if log != nil {
					log("✓ " + eh.Label + "：重新启用")
				}
			case "attach":
				if len(allInboundIDs) > 0 {
					if err := p.AttachClient(eh.Email, allInboundIDs); err != nil {
						if log != nil {
							log("✗ " + eh.Label + "：挂到入口失败：" + err.Error())
						}
					} else if log != nil {
						log("✓ " + eh.Label + "：已挂到全部入口")
					}
				}
			case "order":
				blockCN, _ := routingBroken(xray)
				EnsureBaseRules(xray, blockCN)
				xrayDirty = true
				if log != nil {
					log("✓ " + eh.Label + "：路由规则顺序已理顺")
				}
			case "proto":
				outTag := ExitOf(xray, PClient{Email: eh.Email}, inbounds)
				if ob := findOutbound(xray, outTag); ob != nil {
					newProto := "http"
					if getStr(ob, "protocol") == "http" {
						newProto = "socks"
					}
					ob["protocol"] = newProto
					xrayDirty = true
					pNames := map[string]string{"socks": "SOCKS5", "http": "HTTP"}
					if log != nil {
						log("✓ " + eh.Label + "：出站协议改成了 " + pNames[newProto])
					}
				}
			case "missing":
				RemoveUserRules(xray, eh.Email, "")
				xrayDirty = true
				if log != nil {
					log("✓ " + eh.Label + "：删掉了指向不存在出站的坏规则，先走 VPS 自己的 IP")
				}
			}
		}
	}

	if len(toEnable) > 0 {
		_ = p.EnableClients(toEnable)
	}
	if xrayDirty {
		if err := p.SaveXray(xray, testURL); err != nil {
			return fmt.Errorf("保存面板设置失败：%v", err)
		}
	}
	return nil
}

package main

import (
	"encoding/json"
	"strings"
)

func isCNBlockRule(rule map[string]any) bool {
	if getStr(rule, "outboundTag") != "blocked" {
		return false
	}
	raw, _ := json.Marshal(rule)
	s := string(raw)
	return strings.Contains(s, `"geoip:cn"`) || strings.Contains(s, `"geosite:cn"`)
}

func isGoogleException(rule map[string]any) bool {
	if getStr(rule, "outboundTag") != "direct" {
		return false
	}
	raw, _ := json.Marshal(rule)
	return strings.Contains(string(raw), "googleapis.cn")
}

func EnsureBaseRules(xray map[string]any, blockCN bool) {
	routing, _ := xray["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
	}
	rawRules, _ := routing["rules"].([]any)

	var userRules []any
	var otherRules []any
	hasPrivate := false
	hasBT := false

	for _, item := range rawRules {
		rm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if isCNBlockRule(rm) || isGoogleException(rm) {
			continue
		}
		if _, hasUser := rm["user"]; hasUser {
			userRules = append(userRules, rm)
			continue
		}
		b, _ := json.Marshal(rm)
		s := string(b)
		if strings.Contains(s, "geoip:private") {
			hasPrivate = true
		}
		if strings.Contains(s, "bittorrent") {
			hasBT = true
		}
		otherRules = append(otherRules, rm)
	}

	var head []any
	if !hasPrivate {
		head = append(head, map[string]any{
			"type":        "field",
			"ip":          []string{"geoip:private"},
			"outboundTag": "blocked",
		})
	}
	if !hasBT {
		head = append(head, map[string]any{
			"type":        "field",
			"protocol":    []string{"bittorrent"},
			"outboundTag": "blocked",
		})
	}

	var tail []any
	if blockCN {
		tail = append(tail,
			map[string]any{
				"type": "field",
				"domain": []string{
					"domain:googleapis.cn",
					"domain:xn--ngstr-lra8j.com",
					"domain:gvt1.com",
					"domain:gvt2.com",
					"full:dl.google.com",
				},
				"outboundTag": "direct",
			},
			map[string]any{
				"type":        "field",
				"ip":          []string{"geoip:cn"},
				"outboundTag": "blocked",
			},
			map[string]any{
				"type":        "field",
				"domain":      []string{"geosite:cn"},
				"outboundTag": "blocked",
			},
		)
	}

	all := append([]any{}, head...)
	all = append(all, userRules...)
	all = append(all, otherRules...)
	all = append(all, tail...)
	routing["rules"] = all
	xray["routing"] = routing

	ensureOutbound(xray, map[string]any{
		"tag":      "direct",
		"protocol": "freedom",
		"settings": map[string]any{},
	})
	ensureOutbound(xray, map[string]any{
		"tag":      "blocked",
		"protocol": "blackhole",
		"settings": map[string]any{},
	})
}

func ensureOutbound(xray map[string]any, ob map[string]any) {
	tag := getStr(ob, "tag")
	if findOutbound(xray, tag) != nil {
		return
	}
	obs, _ := xray["outbounds"].([]any)
	obs = append(obs, ob)
	xray["outbounds"] = obs
}

func InsertUserRule(rules []any, newRule map[string]any) []any {
	insertIdx := len(rules)
	for i, item := range rules {
		rm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if _, hasUser := rm["user"]; hasUser {
			insertIdx = i
			break
		}
		if isCNBlockRule(rm) || isGoogleException(rm) {
			insertIdx = i
			break
		}
	}
	out := make([]any, 0, len(rules)+1)
	out = append(out, rules[:insertIdx]...)
	out = append(out, newRule)
	out = append(out, rules[insertIdx:]...)
	return out
}

func RemoveUserRules(xray map[string]any, email, outboundTag string) {
	routing, _ := xray["routing"].(map[string]any)
	if routing == nil {
		return
	}
	rawRules, _ := routing["rules"].([]any)
	var keptRules []any
	var removedTags []string

	for _, item := range rawRules {
		rm, ok := item.(map[string]any)
		if !ok {
			keptRules = append(keptRules, item)
			continue
		}
		users := strList(rm["user"])
		if len(users) == 0 {
			keptRules = append(keptRules, item)
			continue
		}
		var remUsers []string
		matched := false
		for _, u := range users {
			if u == email {
				matched = true
			} else {
				remUsers = append(remUsers, u)
			}
		}
		if matched {
			if tag := getStr(rm, "outboundTag"); tag != "" {
				removedTags = append(removedTags, tag)
			}
			if len(remUsers) == 0 {
				continue
			}
			rm["user"] = remUsers
		}
		keptRules = append(keptRules, rm)
	}
	routing["rules"] = keptRules
	xray["routing"] = routing

	if outboundTag != "" {
		removedTags = append(removedTags, outboundTag)
	}
	if len(removedTags) == 0 {
		return
	}

	stillUsed := map[string]bool{}
	for _, item := range keptRules {
		if rm, ok := item.(map[string]any); ok {
			stillUsed[getStr(rm, "outboundTag")] = true
		}
	}

	obs, _ := xray["outbounds"].([]any)
	var keptObs []any
	for _, item := range obs {
		om, ok := item.(map[string]any)
		if !ok {
			keptObs = append(keptObs, item)
			continue
		}
		tag := getStr(om, "tag")
		drop := false
		for _, rt := range removedTags {
			if tag == rt && !stillUsed[tag] && tag != "direct" && tag != "blocked" {
				drop = true
				break
			}
		}
		if !drop {
			keptObs = append(keptObs, item)
		}
	}
	xray["outbounds"] = keptObs
}

func OutboundForUser(xray map[string]any, email string) string {
	routing, _ := xray["routing"].(map[string]any)
	if routing == nil {
		return ""
	}
	rules, _ := routing["rules"].([]any)
	for _, item := range rules {
		rm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, u := range strList(rm["user"]) {
			if u == email {
				return getStr(rm, "outboundTag")
			}
		}
	}
	return ""
}

func findOutbound(xray map[string]any, tag string) map[string]any {
	obs, _ := xray["outbounds"].([]any)
	for _, item := range obs {
		if om, ok := item.(map[string]any); ok && getStr(om, "tag") == tag {
			return om
		}
	}
	return nil
}

package main

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	codeAlias = map[string]string{
		"UK":  "GB",
		"USA": "US",
		"LA":  "US",
		"NY":  "US",
		"SJC": "US",
		"LAX": "US",
		"TYO": "JP",
		"NRT": "JP",
		"HKG": "HK",
		"SIN": "SG",
	}
	reUpperCode = regexp.MustCompile(`(^|[^A-Za-z])([A-Z]{2,3})($|[^A-Za-z])`)
	cnKeywords  = []struct {
		kw   string
		code string
	}{
		{"美国", "US"}, {"洛杉矶", "US"}, {"圣何塞", "US"}, {"纽约", "US"}, {"西雅图", "US"}, {"达拉斯", "US"}, {"硅谷", "US"},
		{"日本", "JP"}, {"东京", "JP"}, {"大阪", "JP"},
		{"香港", "HK"}, {"新加坡", "SG"}, {"台湾", "TW"}, {"台北", "TW"},
		{"韩国", "KR"}, {"首尔", "KR"}, {"英国", "GB"}, {"伦敦", "GB"},
		{"德国", "DE"}, {"法兰克福", "DE"}, {"法国", "FR"}, {"巴黎", "FR"},
		{"加拿大", "CA"}, {"澳大利亚", "AU"}, {"悉尼", "AU"}, {"俄罗斯", "RU"},
		{"印度", "IN"}, {"泰国", "TH"}, {"越南", "VN"}, {"马来西亚", "MY"},
		{"菲律宾", "PH"}, {"印尼", "ID"}, {"土耳其", "TR"}, {"巴西", "BR"},
		{"荷兰", "NL"}, {"瑞士", "CH"}, {"瑞典", "SE"}, {"中国", "CN"},
		{"上海", "CN"}, {"北京", "CN"}, {"广州", "CN"}, {"深圳", "CN"},
	}
)

func flagEmoji(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return ""
	}
	return string([]rune{
		rune(0x1F1E6 + int(cc[0]-'A')),
		rune(0x1F1E6 + int(cc[1]-'A')),
	})
}

func countryOf(label string) string {
	low := strings.ToLower(label)
	for _, item := range cnKeywords {
		if strings.Contains(low, item.kw) {
			return item.code
		}
	}
	for _, m := range reUpperCode.FindAllStringSubmatch(label, -1) {
		token := m[2]
		if mapped, ok := codeAlias[token]; ok {
			return mapped
		}
		if len(token) == 2 {
			return token
		}
	}
	return ""
}

func withFlag(label string) string {
	r, _ := utf8.DecodeRuneInString(label)
	if r >= 0x1F1E6 && r <= 0x1F1FF {
		return label
	}
	cc := countryOf(label)
	if cc == "" {
		return label
	}
	f := flagEmoji(cc)
	if f == "" {
		return label
	}
	return f + " " + label
}

func labelCountry(label string) string {
	rs := []rune(label)
	if len(rs) >= 2 && rs[0] >= 0x1F1E6 && rs[0] <= 0x1F1FF && rs[1] >= 0x1F1E6 && rs[1] <= 0x1F1FF {
		return string([]rune{
			rune('A' + (rs[0] - 0x1F1E6)),
			rune('A' + (rs[1] - 0x1F1E6)),
		})
	}
	return countryOf(label)
}

func flagLines(lines []lineInfo, flag string) []lineInfo {
	if flag == "" {
		return lines
	}
	out := make([]lineInfo, len(lines))
	copy(out, lines)
	for i := range out {
		if strings.HasPrefix(out[i].Name, flag) {
			continue
		}
		oldName := out[i].Name
		newName := flag + " " + oldName
		oldJSON, _ := json.Marshal(oldName)
		newJSON, _ := json.Marshal(newName)
		out[i].Name = newName
		out[i].Clash = strings.Replace(out[i].Clash, "name: "+string(oldJSON), "name: "+string(newJSON), 1)
		if idx := strings.LastIndex(out[i].URI, "#"); idx != -1 {
			out[i].URI = out[i].URI[:idx+1] + url.PathEscape(newName)
		}
	}
	return out
}

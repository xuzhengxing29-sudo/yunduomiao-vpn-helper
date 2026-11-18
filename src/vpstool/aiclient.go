package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type aiPathRule struct {
	canon string
	valid func(string) bool
	hint  string
}

type aiResp struct {
	Status int
	Body   []byte
	URL    string
}

var (
	webHostToAPI = map[string]string{
		"platform.deepseek.com":   "https://api.deepseek.com/v1",
		"chat.deepseek.com":       "https://api.deepseek.com/v1",
		"deepseek.com":            "https://api.deepseek.com/v1",
		"www.deepseek.com":        "https://api.deepseek.com/v1",
		"platform.openai.com":     "https://api.openai.com/v1",
		"chatgpt.com":             "https://api.openai.com/v1",
		"chat.openai.com":         "https://api.openai.com/v1",
		"platform.moonshot.cn":    "https://api.moonshot.cn/v1",
		"kimi.moonshot.cn":        "https://api.moonshot.cn/v1",
		"kimi.com":                "https://api.moonshot.cn/v1",
		"www.kimi.com":            "https://api.moonshot.cn/v1",
		"cloud.siliconflow.cn":    "https://api.siliconflow.cn/v1",
		"siliconflow.cn":          "https://api.siliconflow.cn/v1",
		"docs.siliconflow.cn":     "https://api.siliconflow.cn/v1",
		"bailian.console.aliyun.com": "https://dashscope.aliyuncs.com/compatible-mode/v1",
		"dashscope.aliyun.com":    "https://dashscope.aliyuncs.com/compatible-mode/v1",
		"open.bigmodel.cn":        "https://open.bigmodel.cn/api/paas/v4",
		"bigmodel.cn":             "https://open.bigmodel.cn/api/paas/v4",
		"chatglm.cn":              "https://open.bigmodel.cn/api/paas/v4",
		"console.volcengine.com":  "https://ark.cn-beijing.volces.com/api/v3",
		"aistudio.google.com":     "https://generativelanguage.googleapis.com/v1beta/openai",
		"console.groq.com":        "https://api.groq.com/openai/v1",
		"groq.com":                "https://api.groq.com/openai/v1",
		"console.x.ai":            "https://api.x.ai/v1",
		"x.ai":                    "https://api.x.ai/v1",
	}

	reVerSuffix = regexp.MustCompile(`/v\d+[a-z0-9]*(/|$)`)

	aiHostRules = map[string]aiPathRule{
		"api.deepseek.com": {canon: "/v1"},
		"api.openai.com":   {canon: "/v1"},
		"api.moonshot.cn":  {canon: "/v1"},
		"api.moonshot.ai":  {canon: "/v1"},
		"api.siliconflow.cn":  {canon: "/v1"},
		"api.siliconflow.com": {canon: "/v1"},
		"api.x.ai":            {canon: "/v1"},
		"api.anthropic.com":   {canon: "/v1"},
		"dashscope.aliyuncs.com": {
			canon: "/compatible-mode/v1",
			valid: func(p string) bool { return strings.HasPrefix(p, "/compatible-mode/v") },
		},
		"dashscope-intl.aliyuncs.com": {
			canon: "/compatible-mode/v1",
			valid: func(p string) bool { return strings.HasPrefix(p, "/compatible-mode/v") },
		},
		"open.bigmodel.cn": {
			canon: "/api/paas/v4",
			valid: func(p string) bool {
				return strings.HasPrefix(p, "/api/paas/v") || strings.HasPrefix(p, "/api/coding/paas/v")
			},
		},
		"ark.cn-beijing.volces.com": {
			canon: "/api/v3",
			valid: func(p string) bool { return strings.HasPrefix(p, "/api/v") },
		},
		"openrouter.ai": {
			canon: "/api/v1",
			valid: func(p string) bool { return strings.HasPrefix(p, "/api/v") },
		},
		"generativelanguage.googleapis.com": {
			canon: "/v1beta/openai",
			valid: func(p string) bool { return strings.Contains(p, "/openai") },
		},
		"api.groq.com": {
			canon: "/openai/v1",
			valid: func(p string) bool { return strings.HasPrefix(p, "/openai/v") },
		},
		"localhost:11434": {canon: "/v1"},
		"127.0.0.1:11434": {canon: "/v1"},
	}

	reTokenSplit = regexp.MustCompile(`[^a-z0-9]+`)
)

func pathNonEmpty(p string) bool {
	return p != "" && p != "/"
}

func isLocalHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func aiRuleFor(u *url.URL) (aiPathRule, bool) {
	if r, ok := aiHostRules[strings.ToLower(u.Host)]; ok {
		return r, true
	}
	h, _, err := net.SplitHostPort(u.Host)
	if err == nil {
		if r, ok := aiHostRules[strings.ToLower(h)]; ok {
			return r, true
		}
	}
	return aiPathRule{}, false
}

func normalizeBase(raw string) (string, string, error) {
	s := strings.Trim(strings.TrimSpace(raw), `"'“”‘’`+"`<> \t\r\n")
	s = strings.NewReplacer("：", ":", "／", "/", "。", ".").Replace(s)
	if s == "" {
		return "", "", errors.New("请先填写 API 地址（点上面你用的服务商名字会自动填好）")
	}
	if !strings.Contains(s, "://") {
		hostPart := s
		if idx := strings.IndexAny(s, "/?#"); idx != -1 {
			hostPart = s[:idx]
		}
		h := hostPart
		if sh, _, err := net.SplitHostPort(hostPart); err == nil {
			h = sh
		}
		if isLocalHost(h) {
			s = "http://" + s
		} else {
			s = "https://" + s
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", "", errors.New("API 地址格式不对。请点一下服务商的名字，让地址自动填好")
	}
	hostOnly := strings.ToLower(u.Hostname())
	if net.ParseIP(hostOnly) == nil && !strings.Contains(hostOnly, ".") && hostOnly != "localhost" {
		return "", "", errors.New("API 地址不完整。请点一下服务商的名字，让地址自动填好")
	}

	p := strings.TrimRight(u.Path, "/")
	for _, tail := range []string{"/chat/completions", "/completions", "/models", "/responses"} {
		if strings.HasSuffix(strings.ToLower(p), tail) {
			p = strings.TrimRight(p[:len(p)-len(tail)], "/")
		}
	}

	if mapped, ok := webHostToAPI[strings.ToLower(u.Host)]; ok && (p == "" || !reVerSuffix.MatchString(p)) {
		return mapped, "你填的是网页地址，已经自动改成对应的接口地址：" + mapped, nil
	}

	if rule, ok := aiRuleFor(u); ok {
		validFn := rule.valid
		if validFn == nil {
			validFn = pathNonEmpty
		}
		if !validFn(p) {
			fixed := u.Scheme + "://" + u.Host + rule.canon
			return fixed, "", nil
		}
	}
	return u.Scheme + "://" + u.Host + p, "", nil
}

func cleanKey(raw string) (string, error) {
	s := strings.Trim(strings.TrimSpace(raw), `"'“”‘’`+"`")
	if strings.HasPrefix(strings.ToLower(s), "bearer ") {
		s = strings.TrimSpace(s[7:])
	}
	if s == "" {
		return "", errors.New("请填写 API 密钥")
	}
	for _, r := range s {
		if r > 127 || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return "", errors.New("API 密钥里包含了中文或空格，请重新复制粘贴")
		}
	}
	return s, nil
}

func (a *App) isPanelToken(key string) bool {
	if key == "" {
		return false
	}
	a.mu.Lock()
	if a.panel != nil && a.panel.APIToken == key {
		a.mu.Unlock()
		return true
	}
	a.mu.Unlock()

	matches, _ := filepath.Glob(filepath.Join(exeDir(), "*", "面板信息.txt"))
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err == nil && strings.Contains(string(b), key) {
			return true
		}
	}
	return false
}

func (r *aiResp) isHTML() bool {
	s := strings.ToLower(strings.TrimSpace(string(r.Body)))
	for _, p := range []string{"<!doctype", "<html", "<head", "<body", "<?xml"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func shortURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

func explainNetErr(rawURL string, err error, timeoutSec int) error {
	host := rawURL
	isLocal := false
	if u, e := url.Parse(rawURL); e == nil && u.Host != "" {
		host = u.Host
		isLocal = isLocalHost(u.Hostname())
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("等了 %d 秒，%s 没有回应。\n多半是网络到不了这家服务商：用国外的服务商（OpenAI 等）在国内要先开 VPN；用国内的服务商（DeepSeek 等）开着 VPN 反而可能连不上，关掉再试", timeoutSec, host)
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "no such host"):
		return fmt.Errorf("找不到 %s 这个地址。请检查 API 地址有没有写错，或者网络是否正常", host)
	case strings.Contains(s, "connection refused"), strings.Contains(s, "actively refused"):
		if isLocal {
			return fmt.Errorf("本机的 AI 服务没有启动（%s 拒绝连接）。如果用的是 Ollama，请先把它运行起来", host)
		}
		return fmt.Errorf("%s 拒绝了连接。请检查 API 地址和端口有没有写错", host)
	case strings.Contains(s, "x509"), strings.Contains(s, "certificate"), strings.Contains(s, "tls:"):
		return fmt.Errorf("和 %s 建立安全连接失败（证书问题）。可能是 API 地址写错了；如果开着抓包软件，先关掉再试", host)
	}
	return fmt.Errorf("连不上 AI 服务（%s）：%v\n请检查 API 地址和网络", host, err)
}

func aiRequest(method, rawURL, apiKey string, body []byte, timeout time.Duration) (*aiResp, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "yunduomiao-vpstool/2.8")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	cli := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("API 地址不对：%s 一直在跳转，不是 AI 的接口地址", shortURL(rawURL))
			}
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("API 地址不对：%s 会跳转到 %s，说明它不是 AI 的接口地址。\n请在设置里点一下服务商的名字，让地址自动填好", shortURL(via[0].URL.String()), shortURL(req.URL.String()))
			}
			return nil
		},
	}

	resp, err := cli.Do(req)
	if err != nil {
		var uErr *url.Error
		if errors.As(err, &uErr) && strings.HasPrefix(uErr.Err.Error(), "API 地址不对") {
			return nil, uErr.Err
		}
		return nil, explainNetErr(rawURL, err, int(timeout.Seconds()))
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	return &aiResp{
		Status: resp.StatusCode,
		Body:   respBytes,
		URL:    rawURL,
	}, nil
}

func aiPost(cfg *aiConfig, payload map[string]any, timeout time.Duration) (*aiResp, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := aiRequest("POST", cfg.Base+"/chat/completions", cfg.Key, body, timeout)
	if err != nil {
		return nil, err
	}
	if (resp.Status == 404 || resp.isHTML()) && !reVerSuffix.MatchString(cfg.Base) {
		if !looksLikeModelErr(aiErrText(resp.Body)) {
			resp2, err2 := aiRequest("POST", cfg.Base+"/v1/chat/completions", cfg.Key, body, timeout)
			if err2 == nil && resp2.Status != 404 && !resp2.isHTML() {
				cfg.Base += "/v1"
				_ = saveAI(*cfg)
				return resp2, nil
			}
		}
	}
	return resp, nil
}

type aiChoice struct {
	Choices []struct {
		Message map[string]any `json:"message"`
	} `json:"choices"`
}

func aiErrText(body []byte) string {
	var m map[string]any
	if json.Unmarshal(body, &m) == nil {
		if eObj, ok := m["error"].(map[string]any); ok {
			if msg := getStr(eObj, "message"); msg != "" {
				if len(msg) > 240 {
					return msg[:240] + "..."
				}
				return msg
			}
		}
		if eStr, ok := m["error"].(string); ok && eStr != "" {
			if len(eStr) > 240 {
				return eStr[:240] + "..."
			}
			return eStr
		}
		if msg := getStr(m, "message"); msg != "" {
			if len(msg) > 240 {
				return msg[:240] + "..."
			}
			return msg
		}
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 240 {
		s = s[:240] + "..."
	}
	return s
}

func hasAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func looksLikeToolErr(s string) bool {
	low := strings.ToLower(s)
	return hasAny(low, "tool", "function_call", "functions", "不支持工具", "不支持 function")
}

func looksLikeModelErr(s string) bool {
	low := strings.ToLower(s)
	if looksLikeToolErr(low) {
		return false
	}
	if strings.Contains(low, "model") && hasAny(low, "not found", "not exist", "does not exist", "invalid", "unknown", "unsupported", "no such", "not available") {
		return true
	}
	if strings.Contains(low, "模型") && hasAny(low, "不存在", "不支持", "无效", "未找到", "找不到") {
		return true
	}
	return false
}

func looksLikeBalanceErr(s string) bool {
	low := strings.ToLower(s)
	return hasAny(low, "insufficient", "quota", "balance", "credit", "billing", "arrears", "overdue", "余额", "欠费", "额度")
}

func explainAI(resp *aiResp, model string) error {
	rawMsg := aiErrText(resp.Body)
	host := shortURL(resp.URL)
	quote := ""
	if rawMsg != "" && !resp.isHTML() {
		quote = "\n服务商的原话：" + rawMsg
	}

	if resp.isHTML() {
		bodyLow := strings.ToLower(string(resp.Body))
		if hasAny(bodyLow, "cloudflare", "just a moment", "attention required", "waf", "captcha", "access denied", "forbidden") {
			return fmt.Errorf("请求被 AI 服务商的防火墙拦截了，不是余额或密钥的问题（HTTP %d）。\n最常见的原因是你的出口 IP 不被这家服务商接受：\n· 用国内的服务商（DeepSeek、通义、Kimi、智谱）时，请关掉 VPN 或让它直连再试。开着 VPN 时请求是从海外机房 IP 发出的，容易被拦。\n· 用国外的服务商（OpenAI 等）时反过来，需要开着 VPN。\n· 还不行就确认 API 地址没有填成网页地址（DeepSeek 的接口地址是 https://api.deepseek.com/v1）。", resp.Status)
		}
		return fmt.Errorf("API 地址不对：%s 打开的是一个网页，不是 AI 的接口。%s", host, "\n请打开设置，点一下服务商的名字（比如 DeepSeek），地址会自动填好。接口地址和你登录、充值的网页地址不是同一个。")
	}

	switch resp.Status {
	case 401, 403:
		return fmt.Errorf("API 密钥不对，或者这个密钥没有权限（HTTP %d）。\n请到服务商的网站重新复制密钥再填一次。密钥要和服务商对应：DeepSeek 的密钥只能配 DeepSeek 的地址。面板信息里的「API 令牌」是 3x-ui 面板用的，不能填在这里。%s", resp.Status, quote)
	case 402:
		return fmt.Errorf("AI 账户的余额不足（HTTP %d）。请到服务商的网站充值后再试；刚充值的话等一两分钟。%s", resp.Status, quote)
	case 429:
		if looksLikeBalanceErr(rawMsg) {
			return fmt.Errorf("AI 账户的余额不足（HTTP %d）。请到服务商的网站充值后再试；刚充值的话等一两分钟。%s", resp.Status, quote)
		}
		return errors.New("请求太频繁，被服务商限速了（HTTP 429）。等一分钟再试；一直这样就到服务商的网站看看余额和限速说明。" + quote)
	case 404:
		if looksLikeModelErr(rawMsg) {
			return fmt.Errorf("模型名称不对：服务商不认识「%s」。\n请打开设置，点「保存」，会列出这家服务商能用的模型供你选择。%s", model, quote)
		}
		return fmt.Errorf("API 地址不对（HTTP %d）：%s 不是 AI 的接口。%s%s", resp.Status, resp.URL, "\n请打开设置，点一下服务商的名字（比如 DeepSeek），地址会自动填好。接口地址和你登录、充值的网页地址不是同一个。", quote)
	}

	if looksLikeBalanceErr(rawMsg) {
		return fmt.Errorf("AI 账户的余额不足（HTTP %d）。请到服务商的网站充值后再试；刚充值的话等一两分钟。%s", resp.Status, quote)
	}
	if looksLikeModelErr(rawMsg) {
		return fmt.Errorf("模型名称不对：服务商不认识「%s」。\n请打开设置，点「保存」，会列出这家服务商能用的模型供你选择。%s", model, quote)
	}
	if resp.Status >= 500 {
		return fmt.Errorf("AI 服务商那边出错了或者正忙（HTTP %d），过一会儿再试。%s", resp.Status, quote)
	}
	if resp.Status == 200 {
		return fmt.Errorf("%s 返回的内容不是 AI 的回答，这个地址可能不是「OpenAI 兼容」的接口。%s", host, "\n请打开设置，点一下服务商的名字（比如 DeepSeek），地址会自动填好。接口地址和你登录、充值的网页地址不是同一个。")
	}
	return fmt.Errorf("AI 服务没有接受这次请求（HTTP %d）。%s", resp.Status, quote)
}

func aiListModels(base, apiKey string) ([]string, *aiResp, error) {
	resp, err := aiRequest("GET", base+"/models", apiKey, nil, 15*time.Second)
	if err != nil {
		return nil, nil, err
	}
	if resp.Status != 200 || resp.isHTML() {
		return nil, resp, nil
	}
	var parsed struct {
		Data   []map[string]any `json:"data"`
		Models []any            `json:"models"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, resp, nil
	}
	seen := map[string]bool{}
	var models []string
	add := func(id string) {
		id = strings.TrimSpace(strings.TrimPrefix(id, "models/"))
		if id != "" && !seen[id] {
			seen[id] = true
			models = append(models, id)
		}
	}
	for _, m := range parsed.Data {
		add(getStr(m, "id"))
	}
	for _, item := range parsed.Models {
		switch x := item.(type) {
		case string:
			add(x)
		case map[string]any:
			add(getStr(x, "id"))
			add(getStr(x, "name"))
		}
	}
	sort.Strings(models)
	return models, resp, nil
}

func pickModels(all []string, target string) []string {
	var tokens []string
	for _, t := range reTokenSplit.Split(strings.ToLower(target), -1) {
		if len(t) >= 2 {
			tokens = append(tokens, t)
		}
	}
	var matched, chatModels, others []string
	for _, m := range all {
		low := strings.ToLower(m)
		if hasAny(low, "embed", "whisper", "tts", "dall-e", "moderation", "rerank", "bge-", "audio", "realtime", "image") {
			continue
		}
		hit := false
		for _, tok := range tokens {
			if strings.Contains(low, tok) {
				hit = true
				break
			}
		}
		if hit {
			matched = append(matched, m)
		} else if hasAny(low, "chat", "gpt", "deepseek", "qwen", "kimi", "moonshot", "glm", "claude", "gemini", "llama", "yi-", "doubao") {
			chatModels = append(chatModels, m)
		} else {
			others = append(others, m)
		}
	}
	out := append(append(matched, chatModels...), others...)
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func aiCheck(cfg *aiConfig) (level, text string, models []string, err error) {
	models, resp, err := aiListModels(cfg.Base, cfg.Key)
	if err == nil && (resp.Status == 404 || resp.isHTML()) && !reVerSuffix.MatchString(cfg.Base) {
		if m2, r2, e2 := aiListModels(cfg.Base+"/v1", cfg.Key); e2 == nil && r2.Status == 200 && len(m2) > 0 {
			cfg.Base += "/v1"
			_ = saveAI(*cfg)
			models, resp = m2, r2
		}
	}
	if err == nil && resp != nil && (resp.Status == 401 || resp.Status == 403 || resp.Status == 402) {
		return "", "", nil, explainAI(resp, cfg.Model)
	}
	if len(models) > 0 {
		for _, m := range models {
			if m == cfg.Model {
				return "good", "连接成功，密钥和模型都有效。", pickModels(models, cfg.Model), nil
			}
		}
	}

	probePayload := map[string]any{
		"model": cfg.Model,
		"messages": []map[string]string{
			{"role": "user", "content": "hi"},
		},
		"max_tokens": 1,
	}
	pResp, pErr := aiPost(cfg, probePayload, 25*time.Second)
	if pErr != nil {
		return "", "", nil, pErr
	}
	if pResp.Status == 200 && !pResp.isHTML() {
		var ch aiChoice
		if json.Unmarshal(pResp.Body, &ch) == nil && len(ch.Choices) > 0 {
			return "good", "连接成功，可以正常对话。", pickModels(models, cfg.Model), nil
		}
	}
	if len(models) > 0 && looksLikeModelErr(aiErrText(pResp.Body)) {
		picks := pickModels(models, cfg.Model)
		return "warn", fmt.Sprintf("地址和密钥没问题，但这家服务商没有叫「%s」的模型。点一个它有的：", cfg.Model), picks, nil
	}
	return "", "", pickModels(models, cfg.Model), explainAI(pResp, cfg.Model)
}

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

type apiOp struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Summary string `json:"summary"`
	Tag     string `json:"tag,omitempty"`
	Params  string `json:"params,omitempty"`
	Body    string `json:"body,omitempty"`
	search  string
}

var (
	reSecretKey = regexp.MustCompile(`(?i)(password|passwd|token|secret|username|密码|令牌)`)
	rePanelPath = regexp.MustCompile(`^/panel/api/[A-Za-z0-9_\-./:@%]+(\?[A-Za-z0-9_\-.=&%,]*)?$`)
	reShareURI  = regexp.MustCompile(`(?i)\b(vless|vmess|trojan|ss|hysteria2?|hy2|tuic|wireguard|socks5?)://[^\s"'<>]+`)
)

func openURL(u string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
}

func (a *App) apiPanelOpen(w http.ResponseWriter, r *http.Request) {
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	openURL(p.PublicURL)
	writeJSON(w, map[string]any{
		"ok":   true,
		"url":  p.PublicURL,
		"user": p.Username,
	})
}

func resolveRefs(v any, schemas map[string]any, depth int) any {
	if depth > 4 {
		return v
	}
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			if idx := strings.LastIndex(ref, "/"); idx != -1 {
				name := ref[idx+1:]
				if target, ok := schemas[name]; ok {
					return resolveRefs(target, schemas, depth+1)
				}
			}
		}
		out := map[string]any{}
		for k, val := range x {
			out[k] = resolveRefs(val, schemas, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = resolveRefs(val, schemas, depth+1)
		}
		return out
	}
	return v
}

func parseOpenAPI(raw string) []apiOp {
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return nil
	}
	paths, _ := root["paths"].(map[string]any)
	comps, _ := root["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)

	var ops []apiOp
	for p, item := range paths {
		if !strings.HasPrefix(p, "/panel/api/") {
			continue
		}
		methods, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for m, specRaw := range methods {
			spec, ok := specRaw.(map[string]any)
			if !ok {
				continue
			}
			op := apiOp{
				Method:  strings.ToUpper(m),
				Path:    p,
				Summary: getStr(spec, "summary"),
			}
			if tags := strList(spec["tags"]); len(tags) > 0 {
				op.Tag = tags[0]
			}
			if rb, ok := spec["requestBody"]; ok {
				b, _ := json.Marshal(resolveRefs(rb, schemas, 0))
				s := string(b)
				if len(s) > 400 {
					s = s[:400] + "..."
				}
				op.Body = s
			}
			if params, ok := spec["parameters"]; ok {
				b, _ := json.Marshal(resolveRefs(params, schemas, 0))
				s := string(b)
				if len(s) > 300 {
					s = s[:300] + "..."
				}
				op.Params = s
			}
			op.search = strings.ToLower(op.Method + " " + op.Path + " " + op.Summary + " " + op.Tag + " " + getStr(spec, "operationId"))
			ops = append(ops, op)
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		return ops[i].Path+ops[i].Method < ops[j].Path+ops[j].Method
	})
	return ops
}

func searchOps(ops []apiOp, query string, max int) []apiOp {
	words := strings.Fields(strings.ToLower(query))
	if len(words) == 0 {
		if len(ops) > max {
			return ops[:max]
		}
		return ops
	}
	type scored struct {
		op    apiOp
		score int
	}
	var list []scored
	for _, op := range ops {
		score := 0
		pathLow := strings.ToLower(op.Path)
		for _, w := range words {
			if strings.Contains(pathLow, w) {
				score += 3
			} else if strings.Contains(op.search, w) {
				score += 1
			}
		}
		if score > 0 {
			list = append(list, scored{op: op, score: score})
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		return list[i].score > list[j].score
	})
	if len(list) > max {
		list = list[:max]
	}
	out := make([]apiOp, len(list))
	for i, item := range list {
		out[i] = item.op
	}
	return out
}

func (a *App) panelOps() ([]apiOp, error) {
	a.mu.Lock()
	if len(a.cachedOps) > 0 {
		ops := a.cachedOps
		a.mu.Unlock()
		return ops, nil
	}
	a.mu.Unlock()

	p, err := a.loadPanel()
	if err != nil {
		return nil, err
	}
	out, err := p.Remote.RunStdin("", fmt.Sprintf("curl -sS -k -m 15 %q", p.LocalURL+"/panel/api/openapi.json"))
	if err != nil {
		return nil, err
	}
	ops := parseOpenAPI(out)
	a.mu.Lock()
	a.cachedOps = ops
	a.mu.Unlock()
	return ops, nil
}

func (a *App) apiPanelDocs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query string `json:"query"`
	}
	_ = decode(r, &req)
	ops, err := a.panelOps()
	if err != nil {
		fail(w, err)
		return
	}
	results := searchOps(ops, req.Query, 15)
	groups := map[string]int{}
	for _, op := range ops {
		parts := strings.Split(strings.TrimPrefix(op.Path, "/panel/api/"), "/")
		if len(parts) > 0 {
			groups[parts[0]]++
		}
	}
	writeJSON(w, map[string]any{
		"ok":      true,
		"results": results,
		"total":   len(ops),
		"groups":  groups,
	})
}

func secretKey(k string) bool {
	return reSecretKey.MatchString(strings.ToLower(k))
}

func redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		_, hasEmail := x["email"]
		for k, val := range x {
			if secretKey(k) || (hasEmail && k == "id") {
				out[k] = "***"
				continue
			}
			out[k] = redact(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = redact(val)
		}
		return out
	case string:
		trimmed := strings.TrimSpace(x)
		if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
			(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
			var parsed any
			if json.Unmarshal([]byte(trimmed), &parsed) == nil {
				if b, err := json.Marshal(redact(parsed)); err == nil {
					return string(b)
				}
			}
		}
		return reShareURI.ReplaceAllString(x, "***（链接已隐藏）")
	}
	return v
}

func (a *App) apiPanelCall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string         `json:"method"`
		Path   string         `json:"path"`
		Body   map[string]any `json:"body"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method != "GET" && method != "POST" {
		fail(w, fmt.Errorf("只支持 GET 和 POST"))
		return
	}
	if !rePanelPath.MatchString(req.Path) || strings.Contains(req.Path, "..") {
		fail(w, fmt.Errorf("接口路径不合法"))
		return
	}
	if method == "POST" && a.running() {
		fail(w, fmt.Errorf("当前有任务正在执行，请稍候"))
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	var body any
	if method == "POST" && req.Body != nil {
		body = req.Body
	}
	resp, err := p.Call(method, req.Path, body)
	if err != nil {
		fail(w, err)
		return
	}
	var obj any
	_ = json.Unmarshal(resp.Obj, &obj)
	redactedBytes, _ := json.Marshal(redact(obj))
	resultStr := string(redactedBytes)
	note := ""
	if len(resultStr) > 9000 {
		note = fmt.Sprintf("返回内容太长，只保留了前 9000 个字符（共 %d）。需要的话用更具体的接口或参数缩小范围。", len(resultStr))
		resultStr = resultStr[:9000]
	}
	writeJSON(w, map[string]any{
		"ok":     resp.Success,
		"msg":    resp.Msg,
		"result": resultStr,
		"note":   note,
	})
}

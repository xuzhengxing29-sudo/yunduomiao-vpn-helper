package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Panel struct {
	Remote    *Remote
	Username  string
	Password  string
	Port      string
	BasePath  string
	APIToken  string
	LocalURL  string
	PublicURL string
}

type Inbound struct {
	ID       int             `json:"id"`
	Enable   bool            `json:"enable"`
	Port     int             `json:"port"`
	Protocol string          `json:"protocol"`
	Remark   string          `json:"remark"`
	Tag      string          `json:"tag"`
	Settings json.RawMessage `json:"settings"`
	Stream   json.RawMessage `json:"streamSettings"`
}

type PClient struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	Flow       string `json:"flow"`
	Comment    string `json:"comment"`
	Enable     bool   `json:"enable"`
	TotalGB    int64  `json:"totalGB"`
	Up         int64  `json:"up"`
	Down       int64  `json:"down"`
	ExpiryTime int64  `json:"expiryTime"`
	InboundIDs []int  `json:"inboundIds"`
}

type apiResp struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

func parseEnvFile(text string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok {
			v = strings.Trim(v, `'"`)
			v = strings.ReplaceAll(v, `\`, "")
			m[k] = v
		}
	}
	return m
}

func LoadPanel(r *Remote, serverIP string) (*Panel, error) {
	script := `
if [ -f /etc/x-ui/install-result.env ]; then cat /etc/x-ui/install-result.env; fi
echo "---SHOW"
/usr/local/x-ui/x-ui setting -show true 2>/dev/null
echo "---TOKEN"
/usr/local/x-ui/x-ui setting -getApiToken 2>/dev/null
echo "---CERT"
/usr/local/x-ui/x-ui setting -getCert true 2>/dev/null`
	out, err := r.RunStdin("", script)
	if err != nil {
		return nil, fmt.Errorf("读取面板信息失败：%v", err)
	}
	envPart, rest, _ := strings.Cut(out, "---SHOW")
	showPart, rest, _ := strings.Cut(rest, "---TOKEN")
	tokPart, certPart, _ := strings.Cut(rest, "---CERT")

	env := parseEnvFile(envPart)
	p := &Panel{
		Remote:   r,
		Username: env["XUI_USERNAME"],
		Password: env["XUI_PASSWORD"],
		Port:     env["XUI_PANEL_PORT"],
		BasePath: env["XUI_WEB_BASE_PATH"],
		APIToken: env["XUI_API_TOKEN"],
	}
	for _, line := range strings.Split(showPart, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "username":
			if p.Username == "" {
				p.Username = v
			}
		case "port":
			p.Port = v
		case "webBasePath":
			p.BasePath = v
		}
	}
	for _, line := range strings.Split(tokPart, "\n") {
		if _, v, ok := strings.Cut(line, "apiToken:"); ok {
			if tok := strings.TrimSpace(v); tok != "" {
				p.APIToken = tok
			}
		}
	}
	p.BasePath = "/" + strings.Trim(p.BasePath, "/")
	if p.BasePath == "/" {
		p.BasePath = ""
	}
	scheme := "http"
	if strings.Contains(certPart, "cert:") && !strings.Contains(certPart, "cert: \n") {
		scheme = "https"
	}
	p.LocalURL = fmt.Sprintf("%s://127.0.0.1:%s%s", scheme, p.Port, p.BasePath)
	if u := env["XUI_ACCESS_URL"]; u != "" {
		p.PublicURL = u
	} else {
		p.PublicURL = fmt.Sprintf("%s://%s:%s%s/", scheme, serverIP, p.Port, p.BasePath)
	}
	return p, nil
}

func (p *Panel) Call(method, path string, body any) (*apiResp, error) {
	var ctype, bodyStr string
	if body != nil {
		if vals, ok := body.(url.Values); ok {
			ctype = "application/x-www-form-urlencoded"
			bodyStr = vals.Encode()
		} else {
			b, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			ctype = "application/json"
			bodyStr = string(b)
		}
	}
	stdinData := p.APIToken + "\n" + ctype + "\n" + bodyStr
	fullURL := p.LocalURL + path
	script := fmt.Sprintf(`
TOKEN=$(printf '%%s\n' "$DATA" | sed -n 1p)
CTYPE=$(printf '%%s\n' "$DATA" | sed -n 2p)
BODYF=$(mktemp); CFGF=$(mktemp); chmod 600 "$BODYF" "$CFGF"
printf '%%s' "$DATA" | tail -n +3 > "$BODYF"
printf 'header = "Authorization: Bearer %%s"\n' "$TOKEN" > "$CFGF"
args=(-sS -k -m 90 -X %s -K "$CFGF" -w '\n__HTTP__%%{http_code}')
if [ -n "$CTYPE" ]; then args+=(-H "Content-Type: $CTYPE" --data-binary "@$BODYF"); fi
curl "${args[@]}" %q
rc=$?
rm -f "$BODYF" "$CFGF"
exit $rc`, method, fullURL)

	out, err := p.Remote.RunStdin(stdinData, script)
	if err != nil {
		return nil, fmt.Errorf("调用面板接口 %s 失败：%v", path, err)
	}
	idx := strings.LastIndex(out, "__HTTP__")
	if idx == -1 {
		return nil, fmt.Errorf("面板接口 %s 没有返回状态码", path)
	}
	rawBody := strings.TrimSpace(out[:idx])
	code, _ := strconv.Atoi(strings.TrimSpace(out[idx+8:]))
	if code == 404 {
		return nil, fmt.Errorf("接口不存在：%s（3x-ui 版本可能太旧，请先在服务器上运行 x-ui update）", path)
	}
	var resp apiResp
	if err := json.Unmarshal([]byte(rawBody), &resp); err != nil {
		preview := rawBody
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, fmt.Errorf("HTTP %d，返回内容无法解析：%s", code, preview)
	}
	return &resp, nil
}

func okOrErr(resp *apiResp, err error, action string) error {
	if err != nil {
		return fmt.Errorf("%s失败：%v", action, err)
	}
	if !resp.Success {
		return fmt.Errorf("%s失败：%s", action, resp.Msg)
	}
	return nil
}

func asObj(v any) map[string]any {
	switch x := v.(type) {
	case map[string]any:
		return x
	case json.RawMessage:
		var m map[string]any
		if json.Unmarshal(x, &m) == nil && m != nil {
			return m
		}
		var s string
		if json.Unmarshal(x, &s) == nil {
			_ = json.Unmarshal([]byte(s), &m)
		}
		if m != nil {
			return m
		}
	case string:
		var m map[string]any
		if json.Unmarshal([]byte(x), &m) == nil && m != nil {
			return m
		}
	}
	return map[string]any{}
}

func getStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func (p *Panel) Inbounds() ([]Inbound, error) {
	resp, err := p.Call("GET", "/panel/api/inbounds/list", nil)
	if err := okOrErr(resp, err, "读取入站"); err != nil {
		return nil, err
	}
	var list []Inbound
	if err := json.Unmarshal(resp.Obj, &list); err != nil {
		return nil, fmt.Errorf("解析入站失败：%v", err)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})
	return list, nil
}

func (p *Panel) Clients() ([]PClient, error) {
	resp, err := p.Call("GET", "/panel/api/clients/list", nil)
	if err := okOrErr(resp, err, "读取客户端"); err != nil {
		return nil, err
	}
	var list []PClient
	if err := json.Unmarshal(resp.Obj, &list); err != nil {
		return nil, fmt.Errorf("解析客户端失败：%v", err)
	}
	return list, nil
}

func (p *Panel) GetXray() (map[string]any, string, error) {
	resp, err := p.Call("POST", "/panel/api/xray/", nil)
	if err := okOrErr(resp, err, "读取 Xray 配置"); err != nil {
		return nil, "", err
	}
	outer := asObj(resp.Obj)
	rawCfg := getStr(outer, "xraySetting")
	testURL := getStr(outer, "outboundTestUrl")
	xray := asObj(rawCfg)
	return xray, testURL, nil
}

func (p *Panel) SaveXray(xray map[string]any, testURL string) error {
	b, err := json.MarshalIndent(xray, "", "  ")
	if err != nil {
		return err
	}
	vals := url.Values{}
	vals.Set("xraySetting", string(b))
	if testURL != "" {
		vals.Set("outboundTestUrl", testURL)
	}
	resp, err := p.Call("POST", "/panel/api/xray/update", vals)
	return okOrErr(resp, err, "保存 Xray 配置")
}

func (p *Panel) XrayState() (string, string) {
	resp, err := p.Call("GET", "/panel/api/server/status", nil)
	if err != nil || !resp.Success {
		return "", ""
	}
	obj := asObj(resp.Obj)
	xr := asObj(obj["xray"])
	return getStr(xr, "state"), getStr(xr, "errorMsg")
}

func (p *Panel) RestartXray() error {
	resp, err := p.Call("POST", "/panel/api/server/restartXrayService", nil)
	if err := okOrErr(resp, err, "重启 Xray"); err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(1500 * time.Millisecond)
		st, msg := p.XrayState()
		if st == "running" {
			return nil
		}
		if st == "error" && msg != "" {
			return fmt.Errorf("Xray 启动出错：%s", msg)
		}
	}
	return nil
}

func (p *Panel) AddInbound(in map[string]any) (int, error) {
	resp, err := p.Call("POST", "/panel/api/inbounds/add", in)
	if err := okOrErr(resp, err, "创建入站 "+ fmt.Sprint(in["remark"])); err != nil {
		return 0, err
	}
	var created Inbound
	_ = json.Unmarshal(resp.Obj, &created)
	return created.ID, nil
}

func (p *Panel) AddClient(email, comment, flow string, inboundIDs []int) error {
	payload := map[string]any{
		"client": map[string]any{
			"email":      email,
			"enable":     true,
			"flow":       flow,
			"comment":    comment,
			"limitIp":    0,
			"totalGB":    0,
			"expiryTime": 0,
			"tgId":       "",
		},
		"inboundIds": inboundIDs,
	}
	resp, err := p.Call("POST", "/panel/api/clients/add", payload)
	return okOrErr(resp, err, "创建客户端 "+email)
}

func (p *Panel) DelClient(email string) error {
	resp, err := p.Call("POST", "/panel/api/clients/del/"+url.PathEscape(email), nil)
	return okOrErr(resp, err, "删除客户端 "+email)
}

func (p *Panel) AttachClient(email string, inboundIDs []int) error {
	payload := map[string]any{"inboundIds": inboundIDs}
	resp, err := p.Call("POST", "/panel/api/clients/"+url.PathEscape(email)+"/attach", payload)
	return okOrErr(resp, err, "关联客户端 "+email)
}

func (p *Panel) EnableClients(emails []string) error {
	payload := map[string]any{"emails": emails}
	resp, err := p.Call("POST", "/panel/api/clients/bulkEnable", payload)
	return okOrErr(resp, err, "启用客户端")
}

func (p *Panel) EnableInbound(id int) error {
	vals := url.Values{}
	vals.Set("enable", "true")
	resp, err := p.Call("POST", fmt.Sprintf("/panel/api/inbounds/setEnable/%d", id), vals)
	return okOrErr(resp, err, fmt.Sprintf("启用入站 %d", id))
}

func (p *Panel) UpdateClient(email string, fields map[string]any) error {
	resp, err := p.Call("POST", "/panel/api/clients/update/"+url.PathEscape(email), fields)
	return okOrErr(resp, err, "修改线路 "+email)
}

func (p *Panel) ResetTraffic(email string) error {
	resp, err := p.Call("POST", "/panel/api/clients/resetTraffic/"+url.PathEscape(email), nil)
	return okOrErr(resp, err, "重置流量 "+email)
}

func (p *Panel) Onlines() map[string]bool {
	m := map[string]bool{}
	resp, err := p.Call("POST", "/panel/api/clients/onlines", nil)
	if err != nil || !resp.Success {
		return m
	}
	var list []string
	_ = json.Unmarshal(resp.Obj, &list)
	for _, e := range list {
		m[e] = true
	}
	return m
}

func (p *Panel) ServerStatus() (map[string]any, error) {
	resp, err := p.Call("GET", "/panel/api/server/status", nil)
	if err := okOrErr(resp, err, "读取服务器状态"); err != nil {
		return nil, err
	}
	return asObj(resp.Obj), nil
}

func (p *Panel) BackupDB() ([]byte, error) {
	fullURL := p.LocalURL + "/panel/api/server/getDb"
	script := fmt.Sprintf(`
CFGF=$(mktemp); OUTF=$(mktemp); chmod 600 "$CFGF" "$OUTF"
printf 'header = "Authorization: Bearer %%s"\n' "$DATA" > "$CFGF"
code=$(curl -sS -k -m 120 -K "$CFGF" -o "$OUTF" -w '%%{http_code}' %q)
rc=$?
if [ $rc -eq 0 ] && [ "$code" = 200 ]; then echo "__B64__"; base64 -w0 "$OUTF"; else echo "HTTP $code" >&2; rc=1; fi
rm -f "$CFGF" "$OUTF"
exit $rc`, fullURL)
	out, err := p.Remote.RunStdin(p.APIToken, script)
	if err != nil {
		return nil, fmt.Errorf("下载面板备份失败：%v", err)
	}
	_, b64, ok := strings.Cut(out, "__B64__")
	if !ok {
		return nil, fmt.Errorf("面板备份返回异常")
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
}

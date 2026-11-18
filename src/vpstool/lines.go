package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func (a *App) apiLineUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email   string   `json:"email"`
		LimitGB *float64 `json:"limitGB"`
		Expires *string  `json:"expires"`
		Enable  *bool    `json:"enable"`
	}
	if err := decode(r, &req); err != nil || req.Email == "" {
		fail(w, fmt.Errorf("参数不完整"))
		return
	}
	if a.running() {
		fail(w, fmt.Errorf("当前有任务正在执行，请稍候"))
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	fields := map[string]any{}
	if req.LimitGB != nil {
		if *req.LimitGB < 0 {
			fail(w, fmt.Errorf("流量上限不能为负数"))
			return
		}
		fields["totalGB"] = int64(*req.LimitGB * 1024 * 1024 * 1024)
	}
	if req.Expires != nil {
		if *req.Expires == "" {
			fields["expiryTime"] = int64(0)
		} else {
			t, err := time.ParseInLocation("2006-01-02", *req.Expires, time.Local)
			if err != nil {
				fail(w, fmt.Errorf("到期日期格式不对"))
				return
			}
			fields["expiryTime"] = t.Add(24*time.Hour - time.Second).UnixMilli()
		}
	}
	if req.Enable != nil {
		fields["enable"] = *req.Enable
	}
	if err := p.UpdateClient(req.Email, fields); err != nil {
		fail(w, err)
		return
	}
	if err := p.RestartXray(); err != nil {
		fail(w, fmt.Errorf("已保存，但重启 Xray 失败：%v", err))
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiLineReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decode(r, &req); err != nil || req.Email == "" {
		fail(w, fmt.Errorf("参数不完整"))
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	if err := p.ResetTraffic(req.Email); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiStatus(w http.ResponseWriter, r *http.Request) {
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	st, err := p.ServerStatus()
	if err != nil {
		fail(w, err)
		return
	}
	xrayObj := asObj(st["xray"])
	memObj := asObj(st["mem"])
	diskObj := asObj(st["disk"])
	netIO := asObj(st["netIO"])
	netTraffic := asObj(st["netTraffic"])
	var load1 float64
	if loads, ok := st["loads"].([]any); ok && len(loads) > 0 {
		if v, ok := loads[0].(float64); ok {
			load1 = v
		}
	}
	numF := func(m map[string]any, k string) float64 {
		if v, ok := m[k].(float64); ok {
			return v
		}
		return 0
	}
	writeJSON(w, map[string]any{
		"ok":           true,
		"cpu":          numF(st, "cpu"),
		"cores":        int64(numF(st, "cpuCores")),
		"load":         load1,
		"memUsed":      int64(numF(memObj, "current")),
		"memTotal":     int64(numF(memObj, "total")),
		"diskUsed":     int64(numF(diskObj, "current")),
		"diskTotal":    int64(numF(diskObj, "total")),
		"uptime":       int64(numF(st, "uptime")),
		"netUp":        int64(numF(netIO, "up")),
		"netDown":      int64(numF(netIO, "down")),
		"sent":         int64(numF(netTraffic, "sent")),
		"recv":         int64(numF(netTraffic, "recv")),
		"xrayState":    getStr(xrayObj, "state"),
		"xrayVersion":  getStr(xrayObj, "version"),
		"panelVersion": getStr(st, "panelVersion"),
	})
}

func (a *App) apiBackup(w http.ResponseWriter, r *http.Request) {
	sess, err := a.session()
	if err != nil {
		fail(w, err)
		return
	}
	p, err := a.loadPanel()
	if err != nil {
		fail(w, err)
		return
	}
	db, err := p.BackupDB()
	if err != nil {
		fail(w, err)
		return
	}
	fname := "x-ui备份_" + time.Now().Format("20060102-1504") + ".db"
	full := filepath.Join(sess.outDir, fname)
	if err := os.WriteFile(full, db, 0600); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"ok":   true,
		"file": full,
		"size": len(db),
	})
}

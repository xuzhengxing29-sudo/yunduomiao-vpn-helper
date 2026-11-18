package main

import (
	"embed"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

//go:embed kb
var kbFS embed.FS

type kbDoc struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Keywords []string `json:"keywords"`
	Body     string   `json:"body"`
	Custom   bool     `json:"custom"`
}

type aiNote struct {
	Time string `json:"time"`
	Text string `json:"text"`
}

var stopWords = map[string]bool{}

func init() {
	for _, w := range strings.Fields("怎么 么办 什么 为什 怎样 如何 可以 一个 这个 那个 我的 你的 是不 不是 没有 还是 就是 的时 时候 一下 现在 今天 之后 以后 问题 帮我 请问 能不 不能 么样 the and for how what why") {
		stopWords[w] = true
	}
}

func parseDoc(id, raw string, custom bool) kbDoc {
	raw = strings.TrimPrefix(raw, "\ufeff")
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	doc := kbDoc{ID: id, Title: id, Custom: custom}
	bodyStart := 0
	if len(lines) > 0 && strings.HasPrefix(lines[0], "#") {
		doc.Title = strings.TrimSpace(strings.TrimLeft(lines[0], "# "))
		bodyStart = 1
	}
	for bodyStart < len(lines) {
		line := strings.TrimSpace(lines[bodyStart])
		if line == "" {
			bodyStart++
			continue
		}
		if strings.HasPrefix(line, "关键词：") || strings.HasPrefix(line, "关键词:") {
			kwStr := strings.TrimPrefix(strings.TrimPrefix(line, "关键词："), "关键词:")
			doc.Keywords = strings.Fields(kwStr)
			bodyStart++
		}
		break
	}
	doc.Body = strings.TrimSpace(strings.Join(lines[bodyStart:], "\n"))
	return doc
}

func kbDir() string {
	return filepath.Join(exeDir(), "知识库")
}

func loadKB() []kbDoc {
	var docs []kbDoc
	entries, _ := kbFS.ReadDir("kb")
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		b, err := kbFS.ReadFile("kb/" + e.Name())
		if err != nil {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".md")
		docs = append(docs, parseDoc(id, string(b), false))
	}
	customEntries, _ := os.ReadDir(kbDir())
	for _, e := range customEntries {
		if e.IsDir() {
			continue
		}
		low := strings.ToLower(e.Name())
		if !strings.HasSuffix(low, ".md") && !strings.HasSuffix(low, ".txt") {
			continue
		}
		if strings.HasPrefix(e.Name(), "说明") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(kbDir(), e.Name()))
		if err != nil {
			continue
		}
		text := strings.ToValidUTF8(string(b), "")
		docs = append(docs, parseDoc(e.Name(), text, true))
	}
	return docs
}

func terms(q string) []string {
	q = strings.ToLower(q)
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		if t == "" || stopWords[t] || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}

	var ascii []rune
	var cjk []rune
	flushASCII := func() {
		if len(ascii) >= 2 {
			add(string(ascii))
		}
		ascii = ascii[:0]
	}
	flushCJK := func() {
		for i := 0; i+1 < len(cjk); i++ {
			add(string(cjk[i : i+2]))
		}
		for i := 0; i+2 < len(cjk); i++ {
			add(string(cjk[i : i+3]))
		}
		cjk = cjk[:0]
	}

	for _, r := range q {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			flushCJK()
			ascii = append(ascii, r)
		} else if unicode.Is(unicode.Han, r) {
			flushASCII()
			cjk = append(cjk, r)
		} else {
			flushASCII()
			flushCJK()
		}
	}
	flushASCII()
	flushCJK()
	return out
}

func searchKB(docs []kbDoc, query string, max int) []kbDoc {
	ts := terms(query)
	type scored struct {
		doc   kbDoc
		score int
	}
	var list []scored
	for _, d := range docs {
		titleLow := strings.ToLower(d.Title)
		kwLow := strings.ToLower(strings.Join(d.Keywords, " "))
		bodyLow := strings.ToLower(d.Body)
		score := 0
		for _, t := range ts {
			if strings.Contains(titleLow, t) {
				score += 5
			}
			if strings.Contains(kwLow, t) {
				score += 4
			}
			if strings.Contains(bodyLow, t) {
				score += 1
			}
		}
		if score > 0 {
			if d.Custom {
				score += 2
			}
			list = append(list, scored{doc: d, score: score})
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		return list[i].score > list[j].score
	})
	if len(list) > max {
		list = list[:max]
	}
	out := make([]kbDoc, len(list))
	for i, item := range list {
		doc := item.doc
		rs := []rune(doc.Body)
		if len(rs) > 1500 {
			doc.Body = string(rs[:1500]) + "…"
		}
		out[i] = doc
	}
	return out
}

func notesPath() string {
	return filepath.Join(exeDir(), "AI备忘.json")
}

func loadNotes() []aiNote {
	b, err := os.ReadFile(notesPath())
	if err != nil {
		return nil
	}
	var notes []aiNote
	_ = json.Unmarshal(b, &notes)
	return notes
}

func addNote(text string) error {
	text = strings.Join(strings.Fields(text), " ")
	if text == "" {
		return nil
	}
	rs := []rune(text)
	if len(rs) > 200 {
		text = string(rs[:200])
	}
	notes := loadNotes()
	for _, n := range notes {
		if n.Text == text {
			return nil
		}
	}
	notes = append(notes, aiNote{
		Time: time.Now().Format("2006-01-02"),
		Text: text,
	})
	if len(notes) > 30 {
		notes = notes[len(notes)-30:]
	}
	b, err := json.MarshalIndent(notes, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(notesPath(), b, 0600)
}

func (a *App) apiKBSearch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query string `json:"query"`
	}
	_ = decode(r, &req)
	res := searchKB(loadKB(), req.Query, 4)
	writeJSON(w, map[string]any{
		"ok":      true,
		"results": res,
	})
}

func (a *App) apiKBInfo(w http.ResponseWriter, r *http.Request) {
	docs := loadKB()
	builtin := 0
	var custom []string
	for _, d := range docs {
		if d.Custom {
			custom = append(custom, d.Title)
		} else {
			builtin++
		}
	}
	writeJSON(w, map[string]any{
		"ok":      true,
		"builtin": builtin,
		"custom":  custom,
		"notes":   loadNotes(),
	})
}

func (a *App) apiKBOpen(w http.ResponseWriter, r *http.Request) {
	dir := kbDir()
	_ = os.MkdirAll(dir, 0755)
	readme := filepath.Join(dir, "说明.txt")
	if _, err := os.Stat(readme); err != nil {
		_ = os.WriteFile(readme, []byte("# 标题写在第一行\r\n关键词：用空格分开的几个词，方便 AI 找到这篇\r\n\r\n把你自己的资料（.md 或 .txt 文件，UTF-8 编码）放在这个文件夹里，AI 回答问题时就会优先参考。\r\n"), 0644)
	}
	openFolder(dir)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiNoteAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	if err := addNote(req.Text); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) apiNoteClear(w http.ResponseWriter, r *http.Request) {
	_ = os.Remove(notesPath())
	writeJSON(w, map[string]any{"ok": true})
}

func kbPromptPart() string {
	var b strings.Builder
	b.WriteString("\n\n知识库里有这些文章（用 search_knowledge 查询正文）：\n")
	for _, d := range loadKB() {
		b.WriteString("- " + d.Title)
		if d.Custom {
			b.WriteString("（用户补充）")
		}
		b.WriteString("\n")
	}
	notes := loadNotes()
	if len(notes) > 0 {
		b.WriteString("\n你之前为这位用户记下的备忘：\n")
		for _, n := range notes {
			b.WriteString("- [" + n.Time + "] " + n.Text + "\n")
		}
	}
	return b.String()
}

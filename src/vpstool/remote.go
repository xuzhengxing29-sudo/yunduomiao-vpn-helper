package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Remote struct {
	Client      *ssh.Client
	Addr        string
	User        string
	Password    string
	ByKey       bool
	Fingerprint string
	Log         io.Writer
	cwd         string
}

func knownHostsPath() string {
	return filepath.Join(exeDir(), "known_hosts.txt")
}

func dialSSH(addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

func Dial(host, port, user, password, keyPath, keyPass string, confirmHost func(fp string) bool, log io.Writer) (*Remote, error) {
	var auths []ssh.AuthMethod
	byKey := false
	if keyPath != "" {
		raw, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("读取私钥文件失败：%v", err)
		}
		var signer ssh.Signer
		if keyPass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(raw, []byte(keyPass))
		} else {
			signer, err = ssh.ParsePrivateKey(raw)
		}
		if err != nil {
			return nil, fmt.Errorf("私钥无法使用：%v", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
		byKey = true
	}
	if password != "" {
		auths = append(auths,
			ssh.Password(password),
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i := range ans {
					ans[i] = password
				}
				return ans, nil
			}),
		)
	}

	var hostFP string
	hostCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		sum := sha256.Sum256(key.Marshal())
		hostFP = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		khPath := knownHostsPath()
		data, _ := os.ReadFile(khPath)
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == host {
				if fields[1] == hostFP {
					return nil
				}
				return fmt.Errorf("服务器 %s 的身份指纹和上次不一样！\n  上次：%s\n  这次：%s\n如果你重装过系统，删除 %s 里这一行后重试；否则可能有人在冒充你的服务器，请停止操作",
					host, fields[1], hostFP, khPath)
			}
		}
		if confirmHost != nil && !confirmHost(hostFP) {
			return errors.New("你取消了连接")
		}
		if f, err := os.OpenFile(khPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
			_, _ = fmt.Fprintln(f, host+" "+hostFP)
			_ = f.Close()
		}
		return nil
	}

	addr := host + ":" + port
	if strings.Contains(host, ":") {
		addr = "[" + host + "]:" + port
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: hostCallback,
		Timeout:         15 * time.Second,
	}
	cli, err := dialSSH(addr, cfg)
	if err != nil {
		return nil, explainSSHError(err)
	}
	r := &Remote{
		Client:      cli,
		Addr:        addr,
		User:        user,
		Password:    password,
		ByKey:       byKey,
		Fingerprint: hostFP,
		Log:         log,
	}
	if _, err := r.RunStdin("", "true"); err != nil {
		_ = cli.Close()
		return nil, err
	}
	go r.keepAlive()
	return r, nil
}

func explainSSHError(err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "unable to authenticate"):
		return errors.New("用户名或密码不对（复制密码时注意不要多带空格；如果重装过系统，用新密码）")
	case strings.Contains(s, "handshake failed: EOF"), strings.Contains(s, "connection reset"), strings.Contains(s, "handshake failed: read tcp"):
		return errors.New("服务器接了连接又马上断开，或者一直不回应。\n最常见的原因：短时间内登录失败次数太多，服务器把你的 IP 临时限制了。\n请先不要再试，等 15 分钟（最长 1 小时）后用正确的密码连一次；着急的话换个网络（比如手机热点）。\n如果一次都没输错过，可能是你的网络到这台服务器的 SSH 被干扰了，开着 VPN 的 TUN 模式再试。")
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "connection timed out"):
		return errors.New("连不上服务器：超时。请确认 IP 和 SSH 端口正确、服务器已开机；如果你在国内且这台 VPS 的 IP 已被墙，需要先开代理（TUN 模式）")
	case strings.Contains(s, "connection refused"):
		return errors.New("服务器拒绝连接：SSH 端口可能不是 22，或者服务器的 SSH 服务没启动")
	}
	return fmt.Errorf("SSH 连接失败：%v", err)
}

func (r *Remote) keepAlive() {
	t := time.NewTicker(25 * time.Second)
	defer t.Stop()
	for range t.C {
		if _, _, err := r.Client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			return
		}
	}
}

func (r *Remote) RunStdin(stdinData, script string) (string, error) {
	sess, err := r.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("SSH 会话建立失败：%v", err)
	}
	defer sess.Close()

	var fullScript string
	if stdinData != "" {
		b64 := base64.StdEncoding.EncodeToString([]byte(stdinData))
		fullScript = "DATA=$(printf %s '" + b64 + "' | base64 -d)\n" + script + "\n"
	} else {
		fullScript = script + "\n"
	}

	sess.Stdin = strings.NewReader(fullScript)
	var outBuf, errBuf bytes.Buffer
	if r.Log != nil {
		sess.Stdout = io.MultiWriter(&outBuf, r.Log)
		sess.Stderr = io.MultiWriter(&errBuf, r.Log)
	} else {
		sess.Stdout = &outBuf
		sess.Stderr = &errBuf
	}

	cmd := "bash -s"
	if r.User != "root" {
		cmd = "sudo -n bash -s"
	}
	if err := sess.Run(cmd); err != nil {
		combined := lastLines(outBuf.String()+"\n"+errBuf.String(), 8)
		if combined != "" {
			return outBuf.String(), fmt.Errorf("%v\n%s", err, combined)
		}
		return outBuf.String(), err
	}
	return outBuf.String(), nil
}

func (r *Remote) CanConnectFresh() bool {
	if r.Password == "" {
		return true
	}
	cfg := &ssh.ClientConfig{
		User:            r.User,
		Auth:            []ssh.AuthMethod{ssh.Password(r.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}
	cli, err := dialSSH(r.Addr, cfg)
	if err != nil {
		return false
	}
	_ = cli.Close()
	return true
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

type limitBuf struct {
	buf       bytes.Buffer
	truncated bool
}

func (l *limitBuf) Write(p []byte) (int, error) {
	const max = 256 * 1024
	rem := max - l.buf.Len()
	if rem <= 0 {
		l.truncated = true
		return len(p), nil
	}
	if len(p) > rem {
		_, _ = l.buf.Write(p[:rem])
		l.truncated = true
		return len(p), nil
	}
	return l.buf.Write(p)
}

func (l *limitBuf) String() string {
	s := strings.ToValidUTF8(l.buf.String(), "?")
	if l.truncated {
		s += "\n（输出太长，只显示前 256KB）"
	}
	return s
}

func (r *Remote) Exec(cmd string, timeout time.Duration) (string, int, string, error) {
	sess, err := r.Client.NewSession()
	if err != nil {
		return "", -1, r.cwd, fmt.Errorf("SSH 会话建立失败：%v", err)
	}
	defer sess.Close()

	cwdInit := ""
	if r.cwd != "" {
		q := "'" + strings.ReplaceAll(r.cwd, "'", `'\''`) + "'"
		cwdInit = "cd " + q + " 2>/dev/null || true\n"
	}
	wrapped := cwdInit + cmd + "\n__rc=$?\nprintf '\\n__YDM_CWD__%%s\\n' \"$(pwd)\"\nexit $__rc\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(wrapped))
	runCmd := `bash -c "eval \"\$(printf %s '` + b64 + `' | base64 -d)\"" < /dev/null 2>&1`
	if r.User != "root" {
		runCmd = "sudo -n " + runCmd
	}

	var out limitBuf
	sess.Stdout = &out
	sess.Stderr = &out

	done := make(chan error, 1)
	go func() {
		done <- sess.Run(runCmd)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var runErr error
	select {
	case runErr = <-done:
	case <-timer.C:
		_ = sess.Signal(ssh.SIGKILL)
		return out.String() + "\n（超过 " + timeout.String() + " 没有结束，已中断。长时间运行的命令请在后面加 & 或用 nohup）", -1, r.cwd, nil
	}

	raw := out.String()
	if idx := strings.LastIndex(raw, "__YDM_CWD__"); idx != -1 {
		r.cwd = strings.TrimSpace(raw[idx+len("__YDM_CWD__"):])
		raw = strings.TrimSuffix(raw[:idx], "\n")
	}

	exitCode := 0
	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitStatus()
		} else {
			return raw, -1, r.cwd, fmt.Errorf("连接中断：%v", runErr)
		}
	}
	return raw, exitCode, r.cwd, nil
}

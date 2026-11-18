package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const pubKeyHex = "f4d80218d71155ce177f172cfb893dc3e19cdbba08776f70efe122087f400ebd"

var (
	licB32   = base32.StdEncoding.WithPadding(base32.NoPadding)
	licEpoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
)

func group(s string, n int) string {
	var parts []string
	for len(s) > n {
		parts = append(parts, s[:n])
		s = s[n:]
	}
	if s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, "-")
}

func cleanCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func machineCode() string {
	sum := sha256.Sum256([]byte("yunduomiao|" + machineGUID()))
	return group(licB32.EncodeToString(sum[:10]), 4)
}

func licenseMessage(machine string, days uint16) []byte {
	return []byte(fmt.Sprintf("YDM1|%s|%d", cleanCode(machine), days))
}

func verifyLicense(code, machine string, now time.Time) (bool, string, string) {
	raw, err := licB32.DecodeString(cleanCode(code))
	if err != nil || len(raw) != 2+ed25519.SignatureSize {
		return false, "", "授权码格式不对，请检查有没有少复制字符"
	}
	days := binary.BigEndian.Uint16(raw[:2])
	sig := raw[2:]
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, "", "内部公钥错误"
	}
	msg := licenseMessage(machine, days)
	if !ed25519.Verify(pub, msg, sig) {
		return false, "", "这个授权码不是给这台电脑的，请把上面的机器码发给作者重新生成"
	}
	if days == 0 {
		return true, "", ""
	}
	exp := licEpoch.AddDate(0, 0, int(days))
	if exp.AddDate(0, 0, 1).Before(now) {
		return false, exp.Format("2006-01-02"), "授权已于 " + exp.Format("2006-01-02") + " 到期，请联系作者续期"
	}
	return true, exp.Format("2006-01-02"), ""
}

func licensePath() string {
	return filepath.Join(exeDir(), "授权码.txt")
}

func loadLicense() (bool, string, string) {
	data, err := os.ReadFile(licensePath())
	if err != nil {
		return false, "", "还没有激活"
	}
	return verifyLicense(string(data), machineCode(), time.Now())
}

func activate(code string) (string, error) {
	ok, exp, reason := verifyLicense(code, machineCode(), time.Now())
	if !ok {
		if reason == "" {
			reason = "授权码无效"
		}
		return "", errors.New(reason)
	}
	formatted := group(cleanCode(code), 6) + "\n"
	if err := os.WriteFile(licensePath(), []byte(formatted), 0600); err != nil {
		return "", fmt.Errorf("授权码正确，但保存失败：%v（请把程序放到一个普通文件夹里，比如桌面）", err)
	}
	return exp, nil
}

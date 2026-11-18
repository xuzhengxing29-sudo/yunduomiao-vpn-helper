package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type ServerInfo struct {
	OSID    string
	OSVer   string
	Arch    string
	IP      string
	HasXUI  bool
	SSHPort string
}

var defaultSniffing = map[string]any{
	"enabled":      true,
	"destOverride": []string{"http", "tls", "quic"},
	"metadataOnly": false,
	"routeOnly":    false,
}

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func x25519Keypair() (privB64, pubB64 string, err error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(priv.Bytes()), enc.EncodeToString(priv.PublicKey().Bytes()), nil
}

func Preflight(r *Remote, fallbackIP string) (*ServerInfo, error) {
	script := `
. /etc/os-release 2>/dev/null
echo "OSID=$ID"; echo "OSVER=$VERSION_ID"; echo "ARCH=$(uname -m)"
echo "SYSTEMD=$(command -v systemctl >/dev/null && echo yes || echo no)"
echo "XUI=$( [ -x /usr/local/x-ui/x-ui ] && echo yes || echo no)"
echo "SSHPORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"
IP=$(curl -4 -s -m 8 https://api.ipify.org || curl -4 -s -m 8 https://ifconfig.me || true)
echo "IP=$IP"
echo "MEM=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)"
echo "DISK=$(df -m / | awk 'NR==2{print $4}')"`
	out, err := r.RunStdin("", script)
	if err != nil {
		return nil, err
	}
	env := parseEnvFile(out)
	info := &ServerInfo{
		OSID:    env["OSID"],
		OSVer:   env["OSVER"],
		Arch:    env["ARCH"],
		IP:      env["IP"],
		HasXUI:  env["XUI"] == "yes",
		SSHPort: env["SSHPORT"],
	}
	if info.IP == "" {
		info.IP = fallbackIP
	}
	if info.SSHPort == "" {
		info.SSHPort = "22"
	}
	if env["SYSTEMD"] != "yes" {
		return nil, fmt.Errorf("这台服务器不支持 systemd")
	}
	if info.OSID != "ubuntu" && info.OSID != "debian" {
		return nil, fmt.Errorf("暂时只支持 Ubuntu 和 Debian，这台是 %s %s。请在 VPS 后台重装为 Ubuntu 22.04/24.04 或 Debian 12", info.OSID, info.OSVer)
	}
	if info.Arch != "x86_64" && info.Arch != "aarch64" && info.Arch != "arm64" {
		return nil, fmt.Errorf("不支持的 CPU 架构：%s", info.Arch)
	}
	if mem, _ := strconv.Atoi(env["MEM"]); mem > 0 && mem < 400 {
		return nil, fmt.Errorf("内存只有 %s MB，太小了（至少 512 MB）", env["MEM"])
	}
	return info, nil
}

func InstallBase(r *Remote) (bool, error) {
	script := `
timedatectl set-ntp true 2>/dev/null || true
if dpkg -s curl socat openssl nftables fail2ban unattended-upgrades ca-certificates cron tar psmisc >/dev/null 2>&1 \
   && [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" = bbr ]; then echo BASE_SKIP; exit 0; fi
for i in 1 2 3 4 5 6; do
  if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then echo "等待系统自动更新结束..."; sleep 10; else break; fi
done
apt-get update -qq
apt-get install -y -qq curl socat openssl nftables fail2ban unattended-upgrades ca-certificates cron tar psmisc >/dev/null
# 开启 BBR 拥塞控制，提升网速
if ! grep -q 'tcp_congestion_control *= *bbr' /etc/sysctl.conf; then
  printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' >> /etc/sysctl.conf
fi
sysctl -p >/dev/null 2>&1 || true
echo BASE_OK`
	out, err := r.RunStdin("", script)
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "BASE_SKIP"), nil
}

func InstallXUI(r *Remote, serverIP string) error {
	script := fmt.Sprintf(`
if [ -x /usr/local/x-ui/x-ui ]; then echo ALREADY; exit 0; fi
# 申请 IP 证书需要 80 端口空闲
if ss -ltn '( sport = :80 )' | grep -q LISTEN; then echo "80 端口被占用，面板证书可能申请失败" >&2; fi
export XUI_NONINTERACTIVE=1 XUI_SSL_MODE=ip XUI_ENABLE_FAIL2BAN=false XUI_SERVER_IP=%s
curl -fsSL -m 60 https://raw.githubusercontent.com/MHSanaei/3x-ui/main/install.sh -o /root/3x-ui-install.sh
bash /root/3x-ui-install.sh < /dev/null
systemctl is-active x-ui >/dev/null && echo XUI_OK`, serverIP)
	_, err := r.RunStdin("", script)
	return err
}

func MakeHy2Cert(r *Remote) error {
	script := `
mkdir -p /root/cert/hy2
if [ ! -s /root/cert/hy2/server.crt ]; then
  openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /root/cert/hy2/server.key -out /root/cert/hy2/server.crt \
    -subj "/CN=www.bing.com" -days 3650 2>/dev/null
fi
chmod 600 /root/cert/hy2/server.key
test -s /root/cert/hy2/server.crt && echo CERT_OK`
	_, err := r.RunStdin("", script)
	return err
}

func realityInbound(port int, sni, privKey, pubKey string) map[string]any {
	settingsBytes, _ := json.Marshal(map[string]any{
		"clients":    []any{},
		"decryption": "none",
		"encryption": "none",
	})
	streamBytes, _ := json.Marshal(map[string]any{
		"network":       "tcp",
		"security":      "reality",
		"externalProxy": []any{},
		"realitySettings": map[string]any{
			"show":         false,
			"xver":         0,
			"target":       sni + ":443",
			"serverNames":  []string{sni},
			"privateKey":   privKey,
			"minClientVer": "",
			"maxClientVer": "",
			"maxTimediff":  0,
			"shortIds":     []string{randHex(4), randHex(8)},
			"mldsa65Seed":  "",
			"settings": map[string]any{
				"publicKey":     pubKey,
				"fingerprint":   "chrome",
				"serverName":    "",
				"spiderX":       "/",
				"mldsa65Verify": "",
			},
		},
		"tcpSettings": map[string]any{
			"acceptProxyProtocol": false,
			"header":              map[string]any{"type": "none"},
		},
	})
	sniffBytes, _ := json.Marshal(defaultSniffing)
	return map[string]any{
		"remark":         fmt.Sprintf("Reality-%d", port),
		"enable":         true,
		"listen":         "",
		"port":           port,
		"protocol":       "vless",
		"expiryTime":     0,
		"total":          0,
		"tag":            fmt.Sprintf("in-%d-tcp", port),
		"settings":       string(settingsBytes),
		"streamSettings": string(streamBytes),
		"sniffing":       string(sniffBytes),
	}
}

func hy2Inbound(port int, obfsPass string) map[string]any {
	settingsBytes, _ := json.Marshal(map[string]any{
		"clients": []any{},
		"version": 2,
	})
	streamBytes, _ := json.Marshal(map[string]any{
		"network":  "hysteria",
		"security": "tls",
		"hysteriaSettings": map[string]any{
			"version":        2,
			"udpIdleTimeout": 60,
		},
		"tlsSettings": map[string]any{
			"serverName":              "www.bing.com",
			"minVersion":              "1.2",
			"maxVersion":              "1.3",
			"cipherSuites":            "",
			"rejectUnknownSni":        false,
			"disableSystemRoot":       false,
			"enableSessionResumption": false,
			"certificates": []any{
				map[string]any{
					"certificateFile": "/root/cert/hy2/server.crt",
					"keyFile":         "/root/cert/hy2/server.key",
					"ocspStapling":    3600,
					"oneTimeLoading":  false,
					"usage":           "encipherment",
					"buildChain":      false,
				},
			},
			"alpn":          []string{"h3"},
			"echServerKeys": "",
			"settings": map[string]any{
				"echConfigList":        "",
				"pinnedPeerCertSha256": []any{},
				"verifyPeerCertByName": "",
			},
		},
		"finalmask": map[string]any{
			"udp": []any{
				map[string]any{
					"type":     "salamander",
					"settings": map[string]any{"password": obfsPass},
				},
			},
		},
	})
	sniffBytes, _ := json.Marshal(defaultSniffing)
	return map[string]any{
		"remark":         fmt.Sprintf("Hy2-%d", port),
		"enable":         true,
		"listen":         "",
		"port":           port,
		"protocol":       "hysteria",
		"expiryTime":     0,
		"total":          0,
		"tag":            fmt.Sprintf("in-%d-udp", port),
		"settings":       string(settingsBytes),
		"streamSettings": string(streamBytes),
		"sniffing":       string(sniffBytes),
	}
}

func EnsureInbounds(p *Panel, sni string, log func(string)) ([]int, error) {
	inbounds, err := p.Inbounds()
	if err != nil {
		return nil, err
	}
	hasReal443 := false
	hasHy2 := map[int]bool{}
	for _, in := range inbounds {
		if in.Protocol == "vless" && in.Port == 443 {
			hasReal443 = true
		}
		if in.Protocol == "hysteria" {
			hasHy2[in.Port] = true
		}
	}

	if hasReal443 {
		if log != nil {
			log("· Reality（TCP 443）已存在，跳过")
		}
	} else {
		priv, pub, err := x25519Keypair()
		if err != nil {
			return nil, err
		}
		if _, err := p.AddInbound(realityInbound(443, sni, priv, pub)); err != nil {
			return nil, err
		}
		if log != nil {
			log("✓ Reality（TCP 443）")
		}
	}

	obfsPass := randHex(12)
	for _, port := range []int{8443, 443} {
		if hasHy2[port] {
			if log != nil {
				log(fmt.Sprintf("· Hysteria2（UDP %d）已存在，跳过", port))
			}
			continue
		}
		if _, err := p.AddInbound(hy2Inbound(port, obfsPass)); err != nil {
			return nil, err
		}
		if log != nil {
			log(fmt.Sprintf("✓ Hysteria2（UDP %d）", port))
		}
	}

	updated, err := p.Inbounds()
	if err != nil {
		return nil, err
	}
	var ids []int
	for _, in := range updated {
		if (in.Protocol == "vless" && in.Port == 443) || (in.Protocol == "hysteria" && (in.Port == 443 || in.Port == 8443)) {
			ids = append(ids, in.ID)
		}
	}
	return ids, nil
}

func VerifyListening(r *Remote) error {
	out, err := r.RunStdin("", "ss -tlnp | grep -q ':443 ' && echo T443; ss -ulnp | grep -q ':443 ' && echo U443; ss -ulnp | grep -q ':8443 ' && echo U8443; true")
	if err != nil {
		return err
	}
	labels := map[string]string{
		"T443":  "Reality(TCP 443)",
		"U443":  "Hysteria2(UDP 443)",
		"U8443": "Hysteria2(UDP 8443)",
	}
	var missing []string
	for _, k := range []string{"T443", "U443", "U8443"} {
		if !strings.Contains(out, k) {
			missing = append(missing, labels[k])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("这些端口没有在监听：%s（可能被其他程序占用，或 Xray 配置有误）", strings.Join(missing, "、"))
	}
	return nil
}

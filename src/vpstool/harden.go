package main

import (
	"fmt"
	"strings"
)

func HardenBasics(r *Remote, sshPort string) error {
	script := fmt.Sprintf(`
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = %s
EOF
systemctl enable --now unattended-upgrades fail2ban >/dev/null 2>&1
systemctl restart fail2ban
sleep 2
systemctl is-active fail2ban >/dev/null && echo F2B_OK`, sshPort)
	_, err := r.RunStdin("", script)
	return err
}

func FirewallScript(sshPort, panelPort string) string {
	seen := map[string]bool{}
	var ports []string
	for _, p := range []string{sshPort, "443", panelPort} {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return fmt.Sprintf(`#!/usr/sbin/nft -f
table inet vpsfw
delete table inet vpsfw
table inet vpsfw {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto icmp accept
    meta l4proto ipv6-icmp accept
    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
    tcp dport { %s } accept
    udp dport { 443, 8443 } accept
  }
}
`, strings.Join(ports, ", "))
}

func ApplyFirewall(r *Remote, sshPort, panelPort string) error {
	fw := FirewallScript(sshPort, panelPort)
	setup := `
systemd-run --unit=fwrollback --on-active=180 /bin/sh -c 'nft delete table inet vpsfw 2>/dev/null || true' >/dev/null 2>&1 || true
cat > /etc/nftables.conf <<'EOF'
` + fw + `EOF
nft -f /etc/nftables.conf`
	if _, err := r.RunStdin("", setup); err != nil {
		return fmt.Errorf("防火墙规则应用失败：%v", err)
	}
	if !r.CanConnectFresh() {
		_, _ = r.RunStdin("", "nft delete table inet vpsfw 2>/dev/null; systemctl stop fwrollback.timer 2>/dev/null; true")
		return fmt.Errorf("开启防火墙后无法用新连接登录 SSH，已自动撤销防火墙")
	}
	_, err := r.RunStdin("", "systemctl stop fwrollback.timer 2>/dev/null; systemctl enable nftables >/dev/null 2>&1; nft list table inet vpsfw >/dev/null && echo FW_OK")
	return err
}

func SetupACMEHooks(r *Remote) (bool, error) {
	script := `
CONF=$(ls /root/.acme.sh/*_ecc/*.conf 2>/dev/null | head -n1)
if [ -z "$CONF" ]; then echo NO_ACME; exit 0; fi
mkdir -p /root/acme-hooks
cat > /root/acme-hooks/open80.sh <<'EOF'
#!/bin/sh
nft list chain inet vpsfw input 2>/dev/null | grep -q acme-tmp || nft add rule inet vpsfw input tcp dport 80 accept comment acme-tmp 2>/dev/null || true
EOF
cat > /root/acme-hooks/close80.sh <<'EOF'
#!/bin/sh
nft -a list chain inet vpsfw input 2>/dev/null | awk '/acme-tmp/{print $NF}' | while read h; do nft delete rule inet vpsfw input handle "$h"; done
EOF
chmod 700 /root/acme-hooks/*.sh
sed -i '/^Le_PreHook=/d;/^Le_PostHook=/d' "$CONF"
echo "Le_PreHook='/root/acme-hooks/open80.sh'" >> "$CONF"
echo "Le_PostHook='/root/acme-hooks/close80.sh'" >> "$CONF"
# 续期会重启面板（VPN 断几秒），改到 UTC 20:43（北京时间 04:43）每天检查一次
( crontab -l 2>/dev/null | grep -v 'acme.sh --cron'; echo '43 20 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null' ) | crontab -
/root/acme-hooks/open80.sh; /root/acme-hooks/close80.sh
nft list chain inet vpsfw input 2>/dev/null | grep -c acme-tmp || true
echo ACME_OK`
	out, err := r.RunStdin("", script)
	if err != nil {
		return false, err
	}
	return !strings.Contains(out, "NO_ACME"), nil
}

func CheckHardening(r *Remote, sshPort, panelPort string) (basicsOK, fwOK, acmeOK bool) {
	q := func(s string) string {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	script := fmt.Sprintf(`
SSHP=%s; PANELP=%s
b=no
[ "$(systemctl is-active fail2ban 2>/dev/null)" = active ] && grep -qsx "port = $SSHP" /etc/fail2ban/jail.local \
  && grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades && b=yes
echo "BASICS=$b"
f=yes
T=$(nft list table inet vpsfw 2>/dev/null)
echo "$T" | grep -q 'policy drop' || f=no
for p in $SSHP 443 $PANELP; do [ -z "$p" ] || echo "$T" | grep 'tcp dport' | grep -qw "$p" || f=no; done
for p in 443 8443; do echo "$T" | grep 'udp dport {' | grep -qw "$p" || f=no; done
[ "$(systemctl is-enabled nftables 2>/dev/null)" = enabled ] || f=no
grep -qs vpsfw /etc/nftables.conf || f=no
systemctl is-active fwrollback.timer >/dev/null 2>&1 && f=no
echo "FW=$f"
a=yes
CONF=$(ls /root/.acme.sh/*_ecc/*.conf 2>/dev/null | head -n1)
if [ -n "$CONF" ]; then
  grep -qs "Le_PreHook='/root/acme-hooks/open80.sh'" "$CONF" && [ -x /root/acme-hooks/close80.sh ] \
    && crontab -l 2>/dev/null | grep -q '^43 20 .*acme.sh --cron' || a=no
fi
echo "ACME=$a"`, q(sshPort), q(panelPort))
	out, err := r.RunStdin("", script)
	if err != nil {
		return false, false, false
	}
	env := parseEnvFile(out)
	return env["BASICS"] == "yes", env["FW"] == "yes", env["ACME"] == "yes"
}

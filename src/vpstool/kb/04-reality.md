# Reality 线路连不上
关键词：Reality VLESS vision TLS 握手 SNI 伪装 icloud 公钥 shortid 时间
Reality 是伪装成访问正常网站的 TCP 线路，走 TCP 443。
连不上的常见原因：
1. IP 的 TCP 被墙（最常见）：见「TCP 443 连不上」。
2. 设备时间不准：误差大了会握手失败，同步系统时间。
3. 伪装网站（SNI）选得不好：默认用 www.icloud.com。如果想换，需要选支持 TLS 1.3 和 HTTP/2、在国外的大站，并且重新生成配置文件。一般不用改。
4. 配置文件和服务器不一致（重装过面板、重建过入口后公钥变了）：重新生成配置文件并重新导入。
5. 服务器 443 端口被其他程序占用（nginx、caddy 等）：在控制台运行 ss -tlnp | grep :443 查看，停掉占用的程序后在「检测并修复」里重启 Xray。

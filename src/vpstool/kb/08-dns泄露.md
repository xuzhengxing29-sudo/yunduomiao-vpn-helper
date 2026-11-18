# DNS 泄露 / 网站还是知道我在国内
关键词：DNS 泄露 leak 检测 dnsleaktest browserleaks 运营商 fake-ip TUN WebRTC 时区
DNS 泄露：访问网站时域名解析请求没走代理，发给了本地运营商的 DNS，对方可以由此看出你的真实位置。
处理：
1. 使用本软件生成的最新配置文件（已开启 fake-ip 模式，国外域名交给代理解析）。旧配置请「重新生成配置文件」。
2. Clash Verge 里打开「TUN 模式」（比「系统代理」更彻底），并打开「严格路由」。
3. 浏览器关闭「安全 DNS / DNS over HTTPS」里指向国内服务商的设置，或设为自动。
4. 测试网站：https://browserleaks.com/dns 或 https://www.dnsleaktest.com ，结果里不应出现中国的运营商。
其他会暴露位置的因素：浏览器的 WebRTC（可装插件禁用）、系统时区和语言、已登录账号的历史记录、GPS 定位。DNS 修好了仍被识别，多半是这些原因或 IP 本身被标记为代理。

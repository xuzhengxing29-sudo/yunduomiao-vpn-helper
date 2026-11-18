# Google Play 下载一直转圈 / 谷歌服务异常
关键词：Google Play 谷歌商店 下载 转圈 等待中 更新不了 gstatic googleapis 谷歌 YouTube
现象：能打开 Google、YouTube，但 Play 商店下载应用一直「等待中」或转圈。
原因：翻墙模式会屏蔽服务器访问「国内域名/国内 IP」（为了隐蔽）。但谷歌有一部分下载和服务域名（如 *.googleapis.cn、*.gstatic.cn、部分 gvt1 域名）被归类为国内，结果被一起屏蔽了。
处理：运行「检测并修复」，在「路由规则」一项点修复。它会在屏蔽国内规则之前加入谷歌例外。修复后重新导入配置文件，并清除 Play 商店的缓存（设置 → 应用 → Google Play 商店 → 存储 → 清除缓存）再试。
手机上还要确认：代理软件里 Play 商店和「Google Play 服务」没有被分应用代理排除。

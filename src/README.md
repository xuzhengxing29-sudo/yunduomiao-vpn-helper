# 源代码说明（Source Code）

本目录包含项目中两个 Windows 工具程序的源码工程：

- `src/ydmkeygen/`：对应 `云朵喵授权码生成器.exe`（本地 Web 授权码签发工具）
- `src/vpstool/`：对应 `云朵喵VPN搭建助手.exe`（VPS 一键部署、3x-ui 管理、AI 排障助手与自检修复工具）
- 仓库根目录 `使用说明.txt`：从 `云朵喵VPN搭建助手.zip` 中原样提取的纯文本使用说明

> [!NOTE]
> **源码还原与验证说明**
> - **前端页面与知识库（原样提取）**：`ydmkeygen/web/index.html`、`vpstool/web/index.html` 以及 `vpstool/kb/*.md` 共 25 篇文档均直接提取自可执行文件中内嵌的 `embed.FS` 原始资源。
> - **Go 后端代码（逆向重构）**：由于原开发环境源码未保留且当前环境未安装 Go 编译器，`*.go` 与 `go.mod` 是根据 Go 1.24.7 (`GOOS=windows GOARCH=amd64`, `-trimpath`) 可执行文件中的 `pclntab`、`filetab`、Go RTTI 结构体标签、机器指令引用与前端 API 调用契约逐文件重构而成，**尚未在本地执行 `go build` 编译测试**。
> - **静态与逻辑核验**：
>   - `ydmkeygen` 的 Ed25519 私钥种子 (`privSeedHex`) 与 `vpstool/license.go` 的公钥 (`pubKeyHex`) 经密码学派生验证一致，且与 `YDM1|<MachineCode>|<Days>` 签名格式对齐；
>   - `vpstool/web/index.html` 的全部 40 个 `/api/*` 前端调用与 Go 路由及 JSON 字段标签核对一致；
>   - 已清理剔除全部个人本机数据、历史授权记录与真实服务器信息。

---

## 目录结构

```text
src/
├── README.md                    # 本说明文件
├── ydmkeygen/                   # 授权码生成器
│   ├── go.mod                   # module ydmkeygen (go 1.24.7)
│   ├── main.go                  # 本地 HTTP 服务、Ed25519 授权签发与记录读写
│   └── web/
│       └── index.html           # 内嵌前端页面
└── vpstool/                     # VPN 搭建助手
    ├── go.mod                   # module vpstool (go 1.24.7 + x/crypto, x/sys, x/term)
    ├── main.go                  # 程序入口与命令行模式
    ├── gui.go                   # 本地 WebView 服务、/api/* 路由、任务调度与登录记录
    ├── license.go               # 授权码离线验签
    ├── console_windows.go       # Windows 控制台初始化与弹窗提示
    ├── machine_windows.go       # Windows 注册表 MachineGuid 机器码获取
    ├── secret_windows.go        # Windows DPAPI (CryptProtectData) 密码加密存储
    ├── remote.go                # SSH 连接、免密 sudo 检测与命令执行封装
    ├── deploy.go                # 系统环境预检、3x-ui 安装、Reality/Hysteria2 入站配置
    ├── harden.go                # fail2ban、自动安全更新、nftables 防火墙与 acme 续期钩子
    ├── routing.go               # Xray 路由规则编排（直连 / 住宅出口 / 谷歌例外 / 回国模式）
    ├── xui.go                   # 3x-ui OpenAPI 与数据库交互封装
    ├── exits.go                 # 住宅代理解析、出口探测与增删接管
    ├── exitcare.go              # 住宅线路健康检查与一键修复
    ├── lines.go                 # 单条线路配额/到期调整、状态查询与面板备份
    ├── clash.go                 # Clash Meta (Mihomo) .yaml 与移动端分享链接生成
    ├── flags.go                 # 国家/地区识别与国旗 Emoji 匹配
    ├── doctor.go                # 二十余项全面体检与一键修复项执行
    ├── aiclient.go              # 多服务商 AI 对话兼容客户端与连通性检查
    ├── panelai.go               # AI 调用 3x-ui OpenAPI 检索与脱敏桥接
    ├── kb.go                    # 内嵌知识库与用户自定义笔记检索
    ├── tools.go                 # AI 工具调用分发、SSH 执行命令、改密与安全配置接口
    ├── web/
    │   └── index.html           # 内嵌前端界面
    └── kb/
        └── 00-整体流程.md ~ 24-备份恢复.md  # 25 篇内置运维知识库
```

---

## 自行编译（Windows）

若本机已安装 **Go 1.24.7+**，可按如下方式分别编译：

### 1. 编译 VPN 搭建助手 (`vpstool`)

```powershell
cd src/vpstool
go mod tidy
go build -trimpath -ldflags="-s -w" -o 云朵喵VPN搭建助手.exe .
```

### 2. 编译授权码生成器 (`ydmkeygen`)

```powershell
cd src/ydmkeygen
go mod tidy
go build -trimpath -ldflags="-s -w" -o 云朵喵授权码生成器.exe .
```

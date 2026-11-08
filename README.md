# Komari KNS：OneBox 节点与订阅

Komari KNS 是运行在 Komari 插件宿主中的原生插件。它通过 Komari Agent 的 `admin:exec` 为探针部署 OneBox 节点、跟踪远程任务、检查节点端点，并发布受令牌保护的订阅。Komari 服务器上不新增守护进程、容器、数据库或监听端口。

## 功能

- 从 Komari 同步探针机器；新机器的部署策略默认关闭。
- 可只读扫描历史 OneBox 安装的入站；管理员逐个确认后，通过一次性 HTTPS 回调加密导入支持的旧节点。导入不会改 OneBox 配置，导入实例保持外部只读归属。
- 管理 VLESS Reality、Hysteria2、TUIC、AnyTLS、Shadowsocks、Trojan、VMess 实例，支持安装、重配置、重装、启用、停用、卸载和只读状态核查。
- 通过 OneBox 一次性回调和 Agent 远程状态双重核验，避免只凭命令退出码登记节点。
- 解析机器 IP、手动公网地址或 DDNS 域名；支持 IPv4、IPv6、双栈和 NAT 外部端口。地址变化后会重新核对公网映射；发现冲突时自动暂停该实例的订阅发布并在管理页提示。插件只读 DNS，不写 DNS 记录。
- 发布 URI、Mihomo YAML 和 sing-box JSON 订阅；支持创建、筛选、隐藏、轮换和撤销订阅档案。
- 采用原子状态写入、每日滚动备份、AES-256-GCM 凭据与订阅快照加密、订阅令牌哈希和审计记录。每个订阅档案可管理多个令牌，支持独立撤销、宽限轮换、到期时间和使用统计；管理员可导出带口令加密的状态/密钥包。订阅 GET 只读取已生成的快照。
- 卸载前要求最近的 OneBox 状态核查，展示配置、证书、防火墙和共享服务资源影响；共享监听仍被引用时保留对应防火墙规则。

## 运行要求

- Komari 的 MoeJS 插件功能和下述权限：`node`、`allowRoutes`、`allowSystemRPC`。
- 目标探针启用了 Komari Agent 远程控制，Agent 以 root 运行，并可访问 OneBox 固定安装器与软件源。
- KNS 回调地址必须是公网可达的 HTTPS Komari URL。
- SubConverter 使用 `http://23.146.156.234:25500/sub` 作为初始配置；应以管理页显示的地址为准。插件本身的原生订阅也可直接交给客户端，不依赖 SubConverter。
- OneBox 管理操作需要受支持的 Linux、systemd 或 OpenRC、`curl` 或 `wget`、`base64`、`sha256sum`、`jq` 和 sing-box 服务。
- 低资源 LXC 会依据可见 PID/内存余量自动限制 OneBox 操作；具体发现/导入/安装门槛见 [兼容性矩阵](docs/compatibility-matrix.md) 与 OneBox README。门槛触发时任务会说明资源类型；未挂载或宿主隐藏的限制无法预先判断。

具体 Komari、Agent、OneBox、sing-box 和 SubConverter 版本应在目标环境确认后记录。当前版本与环境边界见 [兼容性矩阵](docs/compatibility-matrix.md)。

## 构建与安装

```sh
python3 scripts/package.py
sha256sum -c dist/onebox-bridge.zip.sha256
```

在 Komari 插件管理器上传 `dist/onebox-bridge.zip`。核准插件声明的 `node`、`allowRoutes`、`allowSystemRPC` 权限后启用。ZIP 中包含 `komari-plugin.json`、入口脚本、管理页和本地 KNS 模块。

## 首次配置

1. 打开 Komari 管理菜单中的 **OneBox 节点**。
2. 在设置中填写 Komari 的公网 HTTPS 基地址，例如 `https://status.example.com`。OneBox 回调使用此地址。
3. 检查 SubConverter 地址与目标格式。当前配置默认使用 `http://23.146.156.234:25500/sub`、`clash`。
4. 在机器策略中明确允许要管理的探针，并选择 `auto`、`ipv4`、`ipv6` 或 `dual` 地址模式。部署策略默认关闭。
5. 在机器行点“扫描旧版节点”识别已有 OneBox 入站；需要发布的旧节点可以逐个确认导入。导入前为机器设置可用公网地址或 DDNS；NAT 可在确认时填写公网端口。
6. 对需要新建的节点，设置机器地址并安装 OneBox 实例。
7. 创建订阅档案并保存一次性显示的订阅 URL。可直接使用 KNS 原生 URL，也可使用生成的 SubConverter URL。

插件不会配置反向代理、证书、端口转发、云安全组、NAT 或 DNS 记录。订阅里使用的域名必须由你自己的 DNS 与网络路由正确指向探针。

## 本地验证

```sh
node --test tests/*.test.js
node --check script.js
node --check kns/index.js
python3 -m py_compile scripts/package.py
python3 scripts/package.py
```

这些命令覆盖本地模拟回调、权限策略、状态存储、令牌/凭据保护、订阅格式生成和 ZIP/SBOM 生成；它们不代替真实 Komari、Agent、OneBox 节点或客户端导入验证。状态见 [验收报告](docs/acceptance-report.md)。

## 文档

- [交付项追踪](docs/deliverables.md)
- [数据模型和状态 Schema](docs/data-model.md)
- [状态迁移](docs/migrations.md)
- [管理 API 与错误码](docs/api.md)
- [管理员操作手册](docs/user-guide.md)
- [运维手册](docs/operations.md)
- [安全评估](docs/security-report.md)
- [兼容性矩阵](docs/compatibility-matrix.md)
- [验收测试报告](docs/acceptance-report.md)
- [回滚演练步骤](docs/rollback-drill.md)
- [依赖与许可证盘点](docs/license-report.md)
- [协议样例](docs/protocol-samples/README.md)
- [CycloneDX SBOM](docs/sbom.cdx.json)
- [OneBox KNS 实施说明与验收交接](OneBox_KNS_适配改造说明_2026-11-08.docx)

## 版本

插件包版本为 `1.1.0`；OneBox KNS 适配器固定到已审查的源码提交和 SHA-256，见 [兼容性矩阵](docs/compatibility-matrix.md)。可上传 Komari 的 ZIP 为 `dist/onebox-bridge.zip`。源码仓库为 [liuarui/komari-plugin-kns](https://github.com/liuarui/komari-plugin-kns)，分支 `main`。

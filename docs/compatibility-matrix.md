# 兼容性矩阵与已知边界

## 冻结状态

| 组件 | 本次识别/实现 | 验收状态 |
| --- | --- | --- |
| Komari Server | manifest 声明 `>=1.4.3`。官方 1.4.3 源码已包含本插件所需的路由、cron、系统 RPC、Node `fs`/`crypto`/`url` 等 API；该静态源码核验范围的最低 tag 是 1.4.3，未在该版运行时验收。用户管理后台实际观察到 `1.6.1 (96cf0f7)`，官方 tag 对应提交 `96cf0f79d8cfdf6cc8be54fd1976bbc026d58f7f` | 目标面板已运行 KNS v1.0.0。机器中心页、分开的 OneBox 脚本/内核维护操作、默认订阅档案及临时链接的复制/二维码显示经过目标 UI 操作；临时 token 已撤销。完整安装向导、订阅客户端、响应式/键盘与完整 OneBox 生命周期未验收 |
| Komari Agent | 目标 Agent 版本未提供；使用 `admin:exec` 与 `admin:getSpecificTaskResult` | 一台在线探针只读扫描及两个 Runtime 维护 Job 成功；扫描仍发现一个 OneBox 入站并保留原节点。Agent 版本未知；安装新节点、重配置、启停和卸载未在目标探针执行 |
| OneBox | adapter schema 1，版本 `1.8.0`；[提交 `66c18c3`](https://github.com/liuarui/onebox/commit/66c18c352dc591e58075b6c10468ff7bc3bba233)，脚本版本 `1.0.1`，固定 SHA-256 `9e83c464455d81162170c4e2d33a6b5d8c7e278c959959d86ad431c7ec55ec51` | 目标探针的管理脚本更新操作成功，既有节点配置保持；仅一台 Linux 探针实测，不代表完整 OS/LXC 矩阵；低 PID/内存预检阈值见 OneBox README |
| sing-box | OneBox 共享 `onebox-main` Runtime | 目标探针的独立内核维护操作成功；之后观察到 `1.14.4` 且服务 `active`。未验证真实客户端导入或代理流量连通，也未对该目标二进制执行配置 `check` |
| Mihomo | 输出 Mihomo full/provider YAML | 已检查生成文本片段；未用冻结客户端导入 |
| SubConverter | 可选外部转换；KNS 默认关闭并只接受显式配置的 HTTPS `/sub` 地址。旧状态中的 HTTP 地址会在生成链接时重新校验并被忽略 | 历史上曾用虚构 VLESS URI 对 SubConverter-Extended `v1.9.7` 的 HTTP `/sub` 做只读 GET；这只说明服务接受过合成请求，不证明当前 KNS 会提供该 HTTP 链接、节点清单纯净或客户端兼容。没有向转换器发送真实 KNS token；当前 HTTPS 转换链路和客户端导入仍待验收 |
| 操作系统 | installer 既有支持平台以 OneBox 的 Linux / systemd 或 OpenRC 检测为准；未实测架构清单 | 待目标系统矩阵验证 |
| 客户端 | Mihomo、sing-box、其他客户端版本均未由用户指定 | URI/YAML/JSON 导出；客户端实际导入待验收 |

`Server` 响应头标识 `SubConverter-Extended/v1.9.7`。向其 HTTP `/sub` 发送虚构 URI 和三个 target 的请求均成功返回；该历史测试不证明生产安全或当前 KNS 链接可用。KNS 现在拒绝 HTTP 转换地址，包含旧持久化配置；若管理员显式配置可信 HTTPS 转换器，转换器仍会收到源订阅 URL 与凭据。

## 协议覆盖

| 协议 | OneBox | URI | Mihomo | sing-box | 备注 |
| --- | --- | --- | --- | --- | --- |
| VLESS + Reality | 支持 | 支持 | 支持 | 支持 | 适配器限定 Reality；需客户端实际导入 |
| Trojan + TLS | 支持 | 支持 | 支持 | 支持 | 需 SNI |
| VMess + TLS | 支持 | 支持 | 支持 | 支持 | alterId 固定 0 |
| Shadowsocks | 支持 | 支持 | 支持 | 支持 | 支持列表见 UI；URI 规范有客户端差异 |
| Hysteria2 | 支持 | 支持 | 支持 | 支持 | UDP 健康仅 `unverified`；证书、SNI、ALPN 需实测 |
| TUIC | 支持 | 支持 | 支持 | 支持 | UDP 健康仅 `unverified`；证书、ALPN 需实测 |
| AnyTLS | 支持 | 支持 | 支持 | 支持 | 目标客户端对 AnyTLS 的版本支持需核实 |

## 当前不覆盖

- OneBox 以外的远端安装器/Runtime。
- DNS 服务商写记录、证书签发、NAT 或云安全组 API。
- gRPC/WebSocket 等当前 adapter schema 未支持的传输。
- KNS 内置 Surge、Loon、Quantumult X 原生序列化器；这些格式通过外部 SubConverter target 链接提供，实际转换与客户端导入待验收。
- UDP/QUIC L3 握手和代理可用性检测。
- Komari private_site 下的真实匿名订阅兼容测试。

Komari 兼容字段使用官方 manifest 的 `komari` 约束。为适配 1.4.3 的 Goja 运行时，插件在没有全局构造器时从 `node:url` 取得 `URL` 与 `URLSearchParams`；1.6.1 则提供对应全局。静态源码核验不能替代旧版本真机验收，且修复包仍需在目标服务完成启用复测。参考官方 [Komari 1.4.3 runtime](https://github.com/komari-monitor/komari/tree/1.4.3/pkg/jsruntime) 与 [1.6.1 runtime](https://github.com/komari-monitor/komari/tree/1.6.1/pkg/jsruntime)。sing-box 字段映射参照当前官方配置文档：[TLS](https://sing-box.sagernet.org/configuration/shared/tls/)、[Hysteria2](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)、[TUIC](https://sing-box.sagernet.org/configuration/outbound/tuic/)。

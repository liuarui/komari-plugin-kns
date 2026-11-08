# 兼容性矩阵与已知边界

## 冻结状态

| 组件 | 本次识别/实现 | 验收状态 |
| --- | --- | --- |
| Komari Server | manifest 声明 `>=1.4.3`。官方 1.4.3 源码已包含本插件所需的路由、cron、系统 RPC、Node `fs`/`crypto`/`url` 等 API；该静态源码核验范围的最低 tag 是 1.4.3，未在该版运行时验收。用户管理后台实际观察到 `1.6.1 (96cf0f7)`，官方 tag 对应提交 `96cf0f79d8cfdf6cc8be54fd1976bbc026d58f7f` | 上传后曾因首次缺少 `kns/master.key` 的兼容文件系统 `lstat` 错误而无法启用；v1.1.2 工作区已加入缺失文件兼容修复，重新安装/启用待确认 |
| Komari Agent | 目标 Agent 版本未提供；使用 `admin:exec` 与 `admin:getSpecificTaskResult` | 未在目标探针运行 |
| OneBox | adapter schema 1，版本 `1.3.0`；[提交 `d9b98f0`](https://github.com/liuarui/onebox/commit/d9b98f0fd00fe3c9687697baff5c99e398a020b2)，分支 `codex/kns-adapter` | 安装脚本固定 SHA-256 `f5b4a1fde9b773f7963f558411a11003a71183ddb8201fce55801461f5faa65e`；Linux/LXC 真机未执行；低 PID/内存预检阈值见 OneBox README |
| sing-box | OneBox 共享 `onebox-main` Runtime；实际 target 版本由 OneBox 安装过程决定，未锁定 | 结构通过本地生成/JSON 解析，未对目标二进制 `check` |
| Mihomo | 输出 Mihomo full/provider YAML | 已检查生成文本片段；未用冻结客户端导入 |
| SubConverter | `23.146.156.234:25500` 响应 `/sub` 缺少参数请求（HTTP 400）；服务器首页标识为 SubConverter-Extended，页面声明 GPL-3.0；具体二进制版本未知 | 服务存在；未执行带真实 KNS 订阅的转换 |
| 操作系统 | installer 既有支持平台以 OneBox 的 Linux / systemd 或 OpenRC 检测为准；未实测架构清单 | 待目标系统矩阵验证 |
| 客户端 | Mihomo、sing-box、其他客户端版本均未由用户指定 | URI/YAML/JSON 导出；客户端实际导入待验收 |

本次从用户提供的 SubConverter 主机对 `/version` 进行了只读 GET，返回了 SubConverter-Extended 首页；对 `/sub` 空参数请求返回 HTTP 400。此结果仅证明 HTTP 服务在响应与 `/sub` 路由存在，不能确认构建版本、有效转换、客户端兼容或生产访问控制。

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
- Surge、Loon、Quantumult X 等 P1 订阅格式。
- UDP/QUIC L3 握手和代理可用性检测。
- Komari private_site 下的真实匿名订阅兼容测试。

Komari 兼容字段使用官方 manifest 的 `komari` 约束。为适配 1.4.3 的 Goja 运行时，插件在没有全局构造器时从 `node:url` 取得 `URL` 与 `URLSearchParams`；1.6.1 则提供对应全局。静态源码核验不能替代旧版本真机验收，且修复包仍需在目标服务完成启用复测。参考官方 [Komari 1.4.3 runtime](https://github.com/komari-monitor/komari/tree/1.4.3/pkg/jsruntime) 与 [1.6.1 runtime](https://github.com/komari-monitor/komari/tree/1.6.1/pkg/jsruntime)。sing-box 字段映射参照当前官方配置文档：[TLS](https://sing-box.sagernet.org/configuration/shared/tls/)、[Hysteria2](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)、[TUIC](https://sing-box.sagernet.org/configuration/outbound/tuic/)。

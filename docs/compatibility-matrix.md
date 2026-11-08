# 兼容性矩阵与已知边界

## 冻结状态

| 组件 | 本次识别/实现 | 验收状态 |
| --- | --- | --- |
| Komari Server | 目标主机版本/SHA 未提供；实现依赖 MoeJS `server.route`, `server.cron`, `server.call` | 未在目标服务加载 |
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

Komari 侧基于当前官方插件文档实现 MoeJS CommonJS、本地打包模块、route、cron 与 RPC。实际支持版本需以目标 Komari release 和 permission review 为准：[Komari Plugin Development Guide](https://komari-document.pages.dev/en/dev/plugin/)。sing-box 字段映射参照当前官方配置文档：[TLS](https://sing-box.sagernet.org/configuration/shared/tls/)、[Hysteria2](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)、[TUIC](https://sing-box.sagernet.org/configuration/outbound/tuic/)。

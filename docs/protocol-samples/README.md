# 协议样例

这些文件是用 KNS 当前订阅生成器从合成实例数据自动生成的样例；用户名、UUID、密码、公钥均为演示值，不可连接。`node.example.com` 需替换成真实可达地址。样例只证明格式输出结构，不是第三方客户端导入或实际代理连通性证据。

- `onebox-callback.json`：脱敏形状的 OneBox schema 1 成功回调。
- `subscription-uri.txt`：七种当前协议 URI。
- `mihomo-full.yaml` / `mihomo-provider.yaml`：Mihomo 输出模式。
- `singbox-full.json` / `singbox-outbounds.json`：完整 sing-box 配置和 outbounds 片段。

本次单测 JSON.parse 检查 sing-box 输出，检查 Mihomo 与 URI 关键字段；未锁定客户端版本、未执行实际导入。需要按 [验收报告](../acceptance-report.md) 完成目标客户端证据。

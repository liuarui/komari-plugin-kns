# 安全评估（本地代码审查）

## 范围

评估 KNS 1.1.2 插件源码、远程执行脚本构造、历史节点只读发现/导入、回调、订阅和本地状态存储。未取得目标 Komari 管理凭据、目标 Agent、真实节点或生产反向代理环境；本报告不是渗透测试或线上审计证明。

## 控制措施

- **最小化部署**：机器默认 `deployAllowed:false`；危险远程操作要求管理员、明确 `confirm:true`、幂等键和可选 Komari 2FA。
- **远程执行完整性**：执行 OneBox 安装脚本前从固定 commit URL 下载并核对 SHA-256；请求 JSON 先落入目标机 root-owned、mode 0600 的受保护临时目录，再由 OneBox schema 校验。
- **安全卸载**：卸载前必须通过 Agent 读取 OneBox 当前配置引用图；管理页展示仅删除本实例的资源、保留共享引用，以及重载共享服务的影响。状态预览不完整或超过 5 分钟即拒绝提交卸载。
- **双重结果核对**：一次性 job token 绑定 job/machine/runtime/version；需要 Agent 退出码和 `onebox kns status` 同时吻合。
- **历史节点导入**：发现只保存协议/监听元数据；导入需要管理员逐节点确认、近期扫描结果和一次性 HTTPS 回调。导入节点标为外部只读，不能由 KNS 停用、重配或卸载。
- **秘密保护**：OneBox callback 凭据在内存中加密后再保存；实例凭据和派生订阅正文快照均使用 AES-256-GCM；订阅 token 使用随机 256-bit 值，仅存随机 salt 与 SHA-256 hash。回调 token hash 在首个有效回调后删除；同 body digest 重试可幂等返回 204。
- **路由/输出**：管理路由检查 admin principal；写路由检查 same-origin；订阅接口不允许匿名读取，使用 token。状态 API 和日志不会返回 credential ciphertext、明文 token 或远端输出全文。订阅响应 `no-store`。
- **状态文件**：state 与订阅快照临时文件在原子替换前执行 `fsync`；state/key/订阅快照文件设为 0600，目录 0700；首次创建 master key 使用排他文件打开，读取前用 `existsSync` 判断以兼容 Komari 1.6.1 的缺失路径处理；state 保留滚动快照并支持恢复，订阅正文缓存独立加密且可从 state 重建。
- **升级与旧数据迁移**：插件版本变更及迁移旧版 `onebox-bridge.json` 前先私有复制整个插件存储目录；备份失败或状态来自更新版本时停止加载，不写入状态。
- **离线导出与恢复**：原始 JSON 下载路由已关闭。管理员从同源写路由创建独立口令加密包；PBKDF2-SHA256 派生 AES-256-GCM 密钥，密文包含 state 和恢复用 master key，口令不持久化。导入先校验 AEAD 与 schema，再备份本地 state/key；宿主注入 key 时拒绝不匹配的包。
- **并发/DoS 限制**：批量上限 10，端点与健康探测最大并发 5，KNS 对同一探针的 OneBox 远程任务互斥，每轮最多查询 20 个任务；请求正文上限 1 MiB；token 比较使用常数时间字节比较。

## 已知限制与风险

1. 安装器以 root 在探针执行。SHA pin 降低供应链漂移，但任何 OneBox 脚本变更都要求审查并更新 commit + SHA。
2. HTTP SubConverter 是用户提供的服务地址，且当前默认是 HTTP。订阅 URL 携带 token，源订阅包含节点密码；跨不可信网络时有泄漏风险，应通过 HTTPS 代理。
3. `KNS_MASTER_KEY` 环境变量由宿主配置管理；若未设置，自动生成的 key file 必须和状态备份一起保管。日常滚动状态备份仍包含加密密文与令牌哈希，应按敏感数据保管；离线加密导出口令不可找回。
4. `privateSite` 会允许私有地址输出，必须只用于受控内网；公网客户端可能无法连接。
5. 订阅 token 放在 URL query 中，反向代理访问日志或客户端同步日志可能记录它。建议访问日志脱敏并使用专用受控订阅代理。
6. TLS 健康探测只支持标准 TLS；Reality 做 TCP reachability；UDP/QUIC 为 `unverified`。无法由当前层证明节点可代理流量。
7. Komari route 凭插件权限共用现有服务器监听器；未做目标实例特定的 CSRF、反向代理与 API key 配置实测。

## 验证证据

本地 Node 测试检查管理员策略、回调验证、令牌撤销/幂等重试、多令牌生命周期、NAT 映射冲突、口令加密导出往返解密、密文存储、订阅、原子备份和恢复；静态检查 `console` 日志不输出回调或订阅秘密。测试不是第三方审计，真实运行权限与部署路径仍待 AT 报告标记的目标环境验收。

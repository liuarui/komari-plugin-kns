# 管理 API 与错误码

基础路径 `/api/kns`。插件使用 Komari 现有服务器的 MoeJS routes；管理 API 每次验证 `req.context.principal` 的 admin 角色。写请求还要求同源 `Origin`，或受信 `Bearer` 身份 / `Sec-Fetch-Site: same-origin`。所有 JSON 响应带 `Cache-Control: no-store`。详情见 [Komari 插件开发文档](https://komari-document.pages.dev/en/dev/plugin/)。

## 路由

| 方法与路径 | 权限 | 用途 |
| --- | --- | --- |
| `GET /api/kns/admin/state` | Admin | 状态快照、机器/实例/任务/订阅档案、备份清单。凭据与 token 不返回 |
| `POST /api/kns/admin/action` | Admin + 同源 | 单一动作入口；JSON 请求体见下表 |
| `GET /api/kns/admin/logs?limit=100` | Admin | 最近审计记录和任务摘要，最大 500 |
| `GET /api/kns/admin/export` | Admin | 兼容路径，返回 `405 encrypted_export_required`；原始状态导出已关闭 |
| `POST /api/kns/admin/import` | Admin + 同源 | 校验并恢复口令加密导出；请求体上限 16 MiB，导入前保留本地 state/key 副本 |
| `POST /api/kns/report` | OneBox Bearer token | OneBox 一次性任务回调；不需要管理员 session |
| `GET /api/kns/sub?profile=…&format=…&token=…` | 高熵订阅 token | 输出 URI、Mihomo 或 sing-box 订阅 |
| `GET /api/onebox-bridge/subscribe?token=…` | 旧版 token | 迁移订阅的 URI 兼容路由 |
| `GET /api/onebox-bridge/state` | Admin | 旧版只读状态路由 |

订阅格式为 `uri`、`mihomo-full`、`mihomo-provider`、`singbox-full`、`singbox-outbounds`。GET 只读取已生成的加密快照，不在请求期间构建订阅；响应有 ETag、`Vary: Authorization, Cookie`、`X-Content-Type-Options: nosniff` 和 no-store 缓存控制，并返回快照生成时间、成功数和跳过数。`success` 按输出条目计数（URI 行或配置节点）；`skipped` 按未输出的已发布实例计数。快照尚未生成或来源哈希已过期时返回 `503` 与 `Retry-After: 2`；档案/实例变更会触发生成，另有每 5 分钟兜底刷新。

## `POST /admin/action` 动作

请求头：`Content-Type: application/json`；正文上限 1 MiB。

| `action` | 常用字段 | 返回 |
| --- | --- | --- |
| `machine.policy.update` | `machineUuid`, `policy.deployAllowed`, `policy.addressMode`, `policy.manualAddress`, `policy.ddnsHostname`, `policy.tags` | 更新并返回机器策略 |
| `machine.discover` | `machineUuid`, `idempotencyKey`, 可选 `twoFactorCode` | `202` 只读扫描任务；只返回安全元数据，不含节点凭据 |
| `machine.import` | `machineUuid`, `legacyTag`, `confirm:true`, `idempotencyKey`, 可选 `endpointHost`, `externalPort`, `twoFactorCode` | `202` 一次性导入任务；HTTPS 回调后加密登记为外部只读节点 |
| `settings.update` | `publicBaseUrl`（HTTPS），可选 `converterUrl`, `converterTarget`, `privateSite` | 更新回调、订阅转换和私有地址设置 |
| `install` | `machineUuid`, `protocol`, `listenPort`, `listenAddress`, `options`, 可选 `name`, `tags`, `endpointHost`, `externalPort`, `idempotencyKey`, `confirm:true`, `twoFactorCode` | `202` job |
| `reconfigure`, `reinstall` | 同上并带已有 `instanceId` | `202` job |
| `enable`, `disable`, `uninstall` | `machineUuid`, `instanceId`, `idempotencyKey`, `confirm:true`, 可选 `twoFactorCode` | `202` job |
| `instance.status` | `machineUuid`, `instanceId`, `idempotencyKey` | `202` 只读状态 job；OneBox 返回资源归属、引用计数和卸载影响预览 |
| `instance.publish.update` | `instanceId`, `publish:boolean` | 仅控制是否出现在订阅中 |
| `instance.metadata.update` | `instanceId`, 可选 `name`, `tags`, `endpointHost`, `endpointPort`, `externalPort` | 更新实例展示或端点信息 |
| `instance.deduplicate` | `keepInstanceId`, `confirm:true` | 隐藏完全匹配的重复实例，不卸载远端实例 |
| `profile.create` | `name`, `formats[]`, 可选 `instanceIds`, `machineUuids`, `excludeMachineUuids`, `protocols`, `includeTags`, `addressMode`, `sortBy`, `expiresAt`, `excludeUnhealthy` | `201`，只为白名单格式返回 `subscriptionUrls`；仅启用 `uri` 时返回 SubConverter 链接，明文 token URL 只显示一次 |
| `profile.update` | `profileId`, 上述任意可选档案字段 | 更新档案格式、筛选、排序或过期策略 |
| `profile.token.create` | `profileId`, 可选 `expiresAt` | `201`，新增独立令牌并只为白名单格式返回 URL；每档案最多 50 条令牌记录 |
| `profile.token.revoke` | `profileId`, `tokenId` | `200`，仅撤销指定令牌 |
| `profile.rotate` | `profileId`, 可选 `graceSeconds`（0–604800） | `200`，创建新令牌；旧令牌在宽限期结束后失效，默认宽限为 0 秒 |
| `profile.revoke` | `profileId` | 撤销档案下全部令牌 |
| `backup.export` | `passphrase`（12–256 个字符） | 返回 PBKDF2-SHA256 + AES-256-GCM 加密的完整状态与恢复密钥包；口令不保存 |
| `backup.restore` | `name` | 恢复指定日的状态备份 |

令牌访问统计记录通过身份验证的订阅请求（包括因快照尚未就绪而返回 `503` 的请求），约每分钟持久化一次；异常进程退出最多可能丢失一个刷盘周期的计数。令牌自身的到期时间会被档案到期时间限制。轮换已撤销档案会恢复档案状态并创建一个新令牌，旧令牌仍保持撤销。

加密导出使用独立口令派生密钥，导出正文内含状态与 `masterKey`，外层只暴露 KDF 参数和 AES-GCM 密文。通过管理页可导入此文件；若宿主设置了 `KNS_MASTER_KEY`，导入包中的密钥必须与之匹配。保存口令与导出文件时应分开保管。不要把解密后的状态或密钥放入普通工单/聊天。

`machineUuids`、`protocols` 的空数组代表不限制；包含机器与排除机器同时配置时先做包含筛选，再排除命中的机器。标签按实例标签做“任一匹配”。地址族筛选作用于 Endpoint 中的字面 IPv4/IPv6 地址；域名会保留，由订阅客户端按自身 DNS 能力连接。排序支持 `name`、`protocol`、`endpoint`、`machine`。

安装类动作默认拒绝。探针必须被管理员显式设为 `deployAllowed:true`，并且危险变更需要 `confirm:true` 和有效 `idempotencyKey`。同一机器共享 OneBox runtime 一次只允许一个变更 job。

## OneBox 回调与远程核验

适配器从受保护请求文件读取 schema 1 请求；一次性 token 通过 `Authorization: Bearer …` 提交 `/api/kns/report`。回调绑定 `jobId`、`machineUuid`、`runtime.id=onebox-main` 和适配器版本。令牌第一次成功验证后失效；相同 body digest 重试仍返回 204。插件随后查询 `admin:getSpecificTaskResult`，要求 exit code 0 并核对 OneBox `status`。

远端 Agent 操作只经 Komari `admin:exec` 执行；结果只取任务编号、退出码和匹配 `KNS_STATUS=` / `KNS_DISCOVERY=` 的脱敏 JSON，不把完整 stdout/stderr 写入状态或审计日志。历史导入先核对最新只读扫描结果，再接收绑定到机器和 job 的一次性 HTTPS 回调；导入资源声明 `owned:false, shared:true`，后端会拒绝其生命周期变更。离线 Agent、远程控制关闭或权限错误要在任务区查看 `rpcErrorCode` 与错误提示。

## 主要错误码

| 错误码 | 含义 |
| --- | --- |
| `admin_required`, `csrf_origin` | 缺管理员角色或跨站管理请求 |
| `deployment_not_allowed`, `confirmation_required` | 部署策略未开启或缺少显式确认 |
| `runtime_busy`, `idempotency_conflict` | 共享 runtime 有待处理任务或幂等键复用于不同配置 |
| `endpoint_missing`, `private_endpoint`, `nat_endpoint_missing`, `nat_mapping_conflict` | 地址缺失、DDNS 未稳定、公网地址策略拒绝或公网 NAT 映射冲突 |
| `port_conflict`, `invalid_port` | 监听组合不合法或占用 |
| `invalid_callback`, `callback_mismatch` | OneBox 回调 schema、版本或目标不匹配 |
| `legacy_node_not_importable`, `legacy_node_already_imported`, `discovery_stale`, `legacy_instance_readonly` | 历史节点不受支持、扫描结果过期、节点已导入或该导入节点不允许远端生命周期操作 |
| `public_url_required`, `invalid_public_url` | 未设置公网 HTTPS 回调基地址 |
| `master_key_missing`, `secret_decrypt_failed` | 加密密钥缺失/不匹配或凭据损坏 |
| `legacy_state_corrupt` | 原型状态文件不能安全迁移 |

该表描述稳定的公开错误类别，具体 `message` 会随版本调整。

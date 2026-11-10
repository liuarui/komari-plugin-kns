# 管理 API 与错误码

基础路径 `/api/kns`。插件通过 Komari 插件 route API 在现有服务器注册路由；管理 API 每次验证 `req.context.principal` 的 admin 角色。写请求还要求浏览器 Origin 与请求 Host 相同、与管理员配置的 Komari HTTPS 公网 Origin 相同，或 HTTPS 请求带浏览器提供的 `Sec-Fetch-Site: same-origin`（用于反代上游 Host 被改写的部署）；不会信任任意 `X-Forwarded-*`。缺少 Origin 时只接受 Bearer API 身份。所有 JSON 响应带 `Cache-Control: no-store`。详情见 [Komari 插件开发文档](https://komari-document.pages.dev/en/dev/plugin/)。

## 路由

| 方法与路径 | 权限 | 用途 |
| --- | --- | --- |
| `GET /api/kns/admin/state` | Admin | 状态快照、机器/实例/任务/订阅档案、OneBox Runtime 版本与服务状态、最近 200 条审计记录、审计保留检查点和备份清单。凭据与 token 不返回 |
| `POST /api/kns/admin/action` | Admin + 受信 Origin | 单一动作入口；JSON 请求体见下表 |
| `GET /api/kns/admin/logs?limit=100&before=<event-id>` | Admin | 审计记录分页、保留策略/清理检查点和任务摘要，最大 500；日志保留最近 365 天且最多 16 MiB |
| `GET /api/kns/admin/export` | Admin | 兼容路径，返回 `405 encrypted_export_required`；原始状态导出已关闭 |
| `POST /api/kns/admin/import` | Admin + 受信 Origin | 校验并恢复口令加密导出；请求体上限 16 MiB，导入前保留本地 state/key 副本 |
| `POST /api/kns/report` | OneBox Bearer token | OneBox 一次性任务回调；不需要管理员 session |
| `GET /api/kns/sub?profile=…&format=…&token=…` | 高熵订阅 token | 输出 URI、Mihomo 或 sing-box 订阅 |
| `GET /api/onebox-bridge/subscribe?token=…` | 旧版 token | 迁移订阅的 URI 兼容路由 |
| `GET /api/onebox-bridge/state` | Admin | 旧版只读状态路由 |

KNS 原生订阅格式为 `uri`、`mihomo-full`、`mihomo-provider`、`singbox-full`、`singbox-outbounds`。GET 只读取已生成的加密快照，不在请求期间构建订阅；响应有 ETag、`Vary: Authorization, Cookie`、`X-Content-Type-Options: nosniff` 和 no-store 缓存控制，并返回快照生成时间、成功数和跳过数。`success` 按输出条目计数（URI 行或配置节点）；`skipped` 按未输出的已发布实例计数。快照尚未生成或来源哈希已过期时返回 `503` 与 `Retry-After: 2`；档案/实例变更会触发生成，另有每 5 分钟兜底刷新。订阅档案含 `uri` 且已显式配置 HTTPS 转换器时，创建/轮换令牌的响应还会生成 SubConverter target 链接：`clash`、`clashr`、`surge`、`quan`、`quanx`、`loon`、`surfboard`、`stash`、`mellow`、`singbox`、`ss`、`ssd`、`ssr`、`sssub`、`v2ray`、`v2rayn`、`v2rayng`、`shadowrocket`、`trojan`、`vless`、`hysteria2`、`mixed`。该白名单已从用户配置的 SubConverter-Extended `/sub` 响应核对；这些是外部转换链接，不是 KNS 原生格式，目标无法表达的协议可能被转换器跳过。[上游 target 说明](https://github.com/tindy2013/subconverter/blob/master/README.md#supported-types)

## `POST /admin/action` 动作

请求头：`Content-Type: application/json`；正文上限 1 MiB。管理写动作可附 `expectedRevision`（从状态快照读取）；版本不匹配时服务端返回 `409 state_revision_conflict` 与当前/期望 revision，调用方应保留草稿并重新核对。插件管理页对写动作自动附带此字段。只读 `machine.discover` 基于服务器当前机器和任务状态校验，不因旧 revision 拒绝扫描。

| `action` | 常用字段 | 返回 |
| --- | --- | --- |
| `machine.policy.update` | `machineUuid`, `policy.deployAllowed`, `policy.addressMode`, `policy.manualAddress`, `policy.ddnsHostname`, `policy.tags`, 可选 `policy.managementTags` | 更新并返回机器策略；机器远程安装默认允许，可逐台关闭；该权限不会自动提交安装任务。`managementTags` 中包含 `不纳管` 时管理页默认隐藏该机器 |
| `setup.complete` | `publicBaseUrl`, `defaultNode`（VLESS + Reality 模板）, `autoProvisionNewProbes`, 开启时必须 `confirmAutoProvision:true` | 同步探针、记录既有 UUID 基线、完成初始化并创建默认订阅；返回基线数量及订阅链接；重复调用不会创建第二个默认订阅 |
| `machine.sync` | 无 | 同步探针快照；已配置自动部署策略时，新发现的探针才会入队 |
| `settings.defaults.update` | `defaultNode`, `autoProvisionNewProbes`, 开启时必须 `confirmAutoProvision:true` | 只影响后续新探针；关闭时取消未派发队列，不撤回已派发任务 |
| `autoProvision.retry` | `machineUuid`, `confirm:true` | 仅重试失败且无已登记默认节点、在线、已授权且无活动任务的目标 |
| `install.batch` | `machineUuids[]`, `batchId`, 协议配置, `confirm:true`, 可选 `twoFactorCode` | `202` 逐目标返回已受理/阻断/错误与 Job；相同批次 ID 和参数复用原任务，最多 10 台 |
| `machine.discover` | `machineUuid`, `idempotencyKey` | `202` 单机只读扫描任务；管理页不要求输入 2FA；结果和可纳入节点直接显示在机器卡片中，不含节点凭据 |
| `runtime.script.update` | `machineUuid`, `confirm:true`, `idempotencyKey`, 可选 `twoFactorCode` | `202` 更新 OneBox 管理脚本；要求在线、已授权、30 分钟内扫描发现 OneBox、配置 HTTPS 回调并且共享 Runtime 空闲。以固定 SHA-256 核验产物，并检查 Agent、一次性回调和远端脚本版本/摘要 |
| `runtime.kernel.update` | `machineUuid`, `version:"latest"`, `confirm:true`, `idempotencyKey`, 可选 `twoFactorCode` | `202` 独立升级 sing-box 稳定版内核；影响该机全部 KNS 节点，保持升级前运行/停止状态；以 Agent、一次性回调、内核版本和服务状态双重核验 |
| `machine.import` | `machineUuid`, `legacyTag`, `confirm:true`, `idempotencyKey`, 可选 `name`, `endpointHost`, `externalPort` | `202` 接管任务；迁移入站 tag 并重载共享 sing-box 服务，通过一次性 HTTPS 回调登记节点和凭据；默认按协议、机器名和公网端口命名 |
| `settings.update` | `publicBaseUrl`（HTTPS），可选 `converterUrl`（留空关闭或 HTTPS `/sub` URL）, `converterTarget`（见支持列表）, `privateSite` | 更新回调、订阅转换和私有地址设置；HTTP SubConverter 地址拒绝 |
| `install` | `machineUuid`, `protocol`, `listenPort`, `listenAddress`, `options`, 可选 `name`, `tags`, `endpointHost`, `externalPort`, `idempotencyKey`, `confirm:true`, `twoFactorCode` | `202` job |
| `reconfigure`, `reinstall` | 同上并带已有 `instanceId` | `202` job |
| `enable`, `disable` | `machineUuid`, `instanceId`, `idempotencyKey`, `confirm:true`, 可选 `twoFactorCode` | `202` job |
| `uninstall` | `machineUuid`, `instanceId`, `previewVersion`, `idempotencyKey`, `confirm:true`, 可选 `twoFactorCode` | `202` job；服务端要求绑定最近 5 分钟内的完整状态核查版本，并重新检查登记状态与资源清单 |
| `instance.status` | `machineUuid`, `instanceId`, `idempotencyKey` | `202` 只读状态 job；OneBox 返回资源归属、引用计数和卸载影响预览，KNS 为预览生成版本摘要 |
| `job.retry` | `jobId`, `idempotencyKey`, `confirm:true`, 可选 `twoFactorCode` | 仅对 Komari 明确拒绝且未返回 task ID 的原始失败操作安全重试；相同幂等键复用已创建的重试任务，不同键返回 `409 idempotency_conflict`；重试任务本身不能再次链式重试 |
| `instance.publish.update` | `instanceId`, `publish:boolean` | 仅控制是否出现在订阅中 |
| `instance.metadata.update` | `instanceId`, 可选 `name`, `tags`, `endpointHost`, `endpointPort`, `externalPort` | 更新 KNS 显示信息和订阅连接入口；不修改远端 OneBox 监听或 NAT 转发 |
| `instance.deduplicate` | `keepInstanceId`, `confirm:true` | 隐藏完全匹配的重复实例，不卸载远端实例 |
| `profile.create` | `name`, `formats[]`, 可选 `tokenRequired`（默认 `true`）, `instanceIds`, `machineUuids`, `excludeMachineUuids`, `protocols`, `includeTags`, `addressMode`, `sortBy`, `expiresAt`, `excludeUnhealthy` | `201`，每个令牌保护档案只创建一个有效令牌；返回令牌及白名单格式 `subscriptionUrls`。`tokenRequired:false` 时返回不含令牌的公开链接；含 `uri` 时仅在已配置 HTTPS 转换器后返回受支持的 `converterUrls` |
| `profile.token.show` | `profileId` | `200`，管理员重复取回当前令牌和链接；无令牌档案返回不含 token 的链接；响应 `no-store`。旧版只有 hash 的令牌需先轮换 |
| `profile.token.configure` | `profileId`, `enabled:boolean` | 开启时恢复或生成唯一令牌；关闭时链接无需令牌，任何持有链接的人都可访问；响应 `no-store` |
| `profile.update` | `profileId`, 上述任意可选档案字段 | 更新档案格式、筛选、排序或过期策略 |
| `profile.token.create` | `profileId`, 可选 `expiresAt` | `201`，兼容性接口；若已有有效令牌则返回 `409 token_already_exists`。日常使用“显示”或“轮换” |
| `profile.token.revoke` | `profileId`, `tokenId` | `200`，仅撤销指定令牌 |
| `profile.rotate` | `profileId`, `graceSeconds:0` | `200`，生成唯一新令牌并立即使旧令牌失效；不支持宽限 |

节点卡片的“连接入口 / NAT”通过 `instance.metadata.update` 保存订阅对外地址和外部端口。KNS 只记录外部端口与 TCP/UDP 传输组合；路由器或云网络中的实际转发规则需要管理员另行配置。
| `profile.revoke` | `profileId` | 撤销档案下全部令牌 |
| `backup.export` | `passphrase`（12–256 个字符） | 返回 PBKDF2-SHA256 + AES-256-GCM 加密的完整状态与恢复密钥包；口令不保存 |
| `backup.inspect` | `envelope`, `passphrase` | 解密并预检导入范围、Schema 与旧版密文兼容性，不修改状态 |
| `backup.restore.preview` | `name` | 校验日备份/配对密钥、返回替换范围和当前 revision；有活动任务时拒绝 |
| `backup.restore` | `name`, `confirmPhrase:"恢复"`, `expectedRevision` | 恢复指定日备份；后端再次检查 revision 与活动任务并保留事务副本 |

令牌访问统计记录通过身份验证的订阅请求（包括因快照尚未就绪而返回 `503` 的请求），约每分钟持久化一次；异常进程退出最多可能丢失一个刷盘周期的计数。令牌验证使用带盐 hash；为支持管理员重复查看，状态还保存明文 `token`；公开状态接口不返回该 token，查看/创建/轮换响应设置 `no-store`。令牌自身的到期时间会被档案到期时间限制。轮换已撤销档案会恢复档案状态并创建一个新令牌，旧令牌仍保持撤销。

加密导出使用独立口令派生密钥，导出正文内含状态与 `masterKey`，外层只暴露 KDF 参数和 AES-GCM 密文。通过管理页导入时先调用 `backup.inspect` 解密并预检，再通过 `/admin/import` 携带 `confirmPhrase:"恢复"`、预检时的 `expectedRevision`、文件和口令执行。若宿主设置了 `KNS_MASTER_KEY`，导入包中的密钥必须与之匹配。任何活动远程任务都会阻止导入/恢复；恢复持有进程内维护锁并在替换前保留事务副本。保存口令与导出文件时应分开保管。不要把解密后的状态或密钥放入普通工单/聊天。

`machineUuids`、`protocols` 的空数组代表不限制；包含机器与排除机器同时配置时先做包含筛选，再排除命中的机器。标签按实例标签做“任一匹配”。地址族筛选作用于 Endpoint 中的字面 IPv4/IPv6 地址；域名会保留，由订阅客户端按自身 DNS 能力连接。排序支持 `name`、`protocol`、`endpoint`、`machine`。

安装类动作默认拒绝。探针必须被管理员显式设为 `deployAllowed:true`，并且危险变更需要 `confirm:true` 和有效 `idempotencyKey`。同一机器共享 OneBox runtime 一次只允许一个变更 job。

## OneBox 回调与远程核验

适配器从受保护请求文件读取 schema 1 请求；一次性 token 通过 `Authorization: Bearer …` 提交 `/api/kns/report`。回调绑定 `jobId`、`machineUuid`、`runtime.id=onebox-main` 和适配器版本。令牌第一次成功验证后失效；相同 body digest 重试仍返回 204。插件随后查询 `admin:getSpecificTaskResult`，要求 exit code 0 并核对 OneBox `status`。运行时升级还必须匹配 `KNS_RUNTIME_STATUS=` 和 `operationResult`；版本或服务状态不一致时标记 `needs_reconcile`，不会把提交成功当作更新成功。

远端 Agent 操作只经 Komari `admin:exec` 执行；结果只取任务编号、退出码和匹配 `KNS_STATUS=`、`KNS_DISCOVERY=` 或 `KNS_RUNTIME_STATUS=` 的脱敏 JSON，不把完整 stdout/stderr 写入状态或审计日志。历史导入先核对最新只读扫描结果，再接收绑定到机器和 job 的一次性 HTTPS 回调；导入资源声明 `owned:false, shared:true`，后端会拒绝其生命周期变更。离线 Agent、远程控制关闭或权限错误要在机器卡片的最近操作查看错误提示。

## 主要错误码

| 错误码 | 含义 |
| --- | --- |
| `admin_required`, `csrf_origin` | 缺管理员角色或跨站管理请求 |
| `deployment_not_allowed`, `confirmation_required` | 部署策略未开启或缺少显式确认 |
| `runtime_busy`, `idempotency_conflict` | 共享 runtime 有待处理任务或幂等键复用于不同配置 |
| `uninstall_preview_incomplete`, `uninstall_preview_stale`, `uninstall_preview_changed` | 卸载缺少完整资源预览、预览超过五分钟或请求版本不匹配 |
| `endpoint_missing`, `private_endpoint`, `nat_endpoint_missing`, `nat_mapping_conflict` | 地址缺失、DDNS 未稳定、公网地址策略拒绝或公网 NAT 映射冲突 |
| `port_conflict`, `invalid_port` | 监听组合不合法或占用 |
| `invalid_callback`, `callback_mismatch` | OneBox 回调 schema、版本或目标不匹配 |
| `machine_offline`, `runtime_scan_stale`, `public_url_required` | OneBox 升级前置条件不满足；先恢复在线状态、重新只读扫描或设置 HTTPS 回调地址 |
| `kernel_upgrade_failed`, `kernel_service_state_changed`, `script_digest_mismatch` | 内核升级未通过回滚/服务状态检查，或固定管理脚本摘要不匹配；查看同机任务并核查 Runtime |
| `legacy_node_not_importable`, `legacy_node_already_imported`, `discovery_stale`, `legacy_instance_readonly` | 历史节点不受支持、扫描结果过期、节点已导入或该导入节点不允许远端生命周期操作 |
| `public_url_required`, `invalid_public_url` | 未设置公网 HTTPS 回调基地址 |
| `master_key_missing`, `secret_decrypt_failed` | 加密密钥缺失/不匹配或凭据损坏 |
| `legacy_state_corrupt` | 原型状态文件不能安全迁移 |

该表描述稳定的公开错误类别，具体 `message` 会随版本调整。

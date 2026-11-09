# 数据模型与状态 Schema

插件状态保存于 Komari 提供的 `__storageDir__` 下的 `kns/state.json`。目录、状态、备份、快照和密钥文件权限设为 `0700/0600`（宿主文件系统支持时）。状态与订阅快照写入会在原子 rename 前调用 `fsync` 同步临时文件。Komari 1.6.1 兼容文件系统上，对可选状态/密钥文件先用 `existsSync` 判断，避免对缺失路径的 `readFileSync` 触发 `lstat` 错误。未知字段会保留，当前 schema 版本为 `2`。

## 顶层对象

| 字段 | 说明 |
| --- | --- |
| `schemaVersion`, `pluginVersion`, `revision`, `createdAt`, `updatedAt` | 数据结构版本、最后成功加载此状态的插件版本及递增修订信息 |
| `settings` | 首次设置状态、明确授权的新探针自动部署与历史基线、版本化默认节点模板、HTTPS 回调基地址、SubConverter、固定 OneBox installer SHA、健康/同步间隔、私有站点开关、批量上限 |
| `machines[]` | Komari Agent 探针快照及管理员部署/地址策略 |
| `runtimes[]` | 每台机器上的共享 OneBox `sing-box/onebox-main` 服务引用计数 |
| `instances[]` | 由 KNS 管理的远端实例，保存监听、端点、协议元数据、发布/健康状态、最近一次远端状态/卸载资源预览和加密凭据 |
| `jobs[]` | 授权、远程任务编号、回调摘要、结果核验、批次/幂等标识和受限安全重试参数；不存远程 stdout/stderr |
| `profiles[]` | 订阅格式、过滤条件、档案过期时间及 `tokens[]` 生命周期记录 |
| `audit[]` | 最近 1000 条管理动作缓存；完整受保留策略管理的追加式 JSONL 日志另存于 `kns/audit/`，不记录订阅 token 或节点凭据 |
| `legacyNodes[]` | 从原 onebox-bridge 数据迁移的加密 URI |
| `lastSnapshotAt`, `snapshotPending` | 周期/事件快照标记 |

机器快照可包含最近一次管理员触发的 `discoveredAt` 与 `discoveredNodes[]`。该数组仅允许保存安全发现字段（tag、协议、监听地址/端口/传输、托管标记、可导入性、非敏感协议选项和原因）；不得保存凭据或原始 inbound。经明确导入的实例使用 `managedBy:"legacy_import"`、`ownership:"external"`、`readOnly:true` 和 `legacyTag` 标记；凭据以明文 `credential` 保存（state 文件权限 `0600`）；旧版 `credentialCiphertext` 仅作迁移兼容。外部只读实例可发布或隐藏，但不能通过 KNS 修改、停用或卸载 OneBox 配置。

订阅正文缓存与 state 备份快照分开保存于 `kns/subscriptions/<sha256(profileId,format)>.json`。文件为 `0600` 的明文 JSON 记录（含正文、内容 SHA-256、生成时间、规则版本、成功数、跳过数和来源哈希）；正文不再使用 master key 加密。完整记录写入权限为 `0600` 的临时文件后原子替换；记录包含内容 SHA-256、生成时间、规则版本、成功数、跳过数和来源哈希。成功数按输出条目计数（URI 行或配置节点），跳过数按未输出的已发布实例计数。档案/实例状态变化会触发事件刷新，每 5 分钟兜底；订阅 GET 不调用生成器，并会校验本地来源哈希。状态已变化而快照尚未更新时，GET 会从 state 直接构建本次响应并触发后台刷新；只有直接构建也失败时才返回 `503 Retry-After: 2`。档案撤销、过期或移除格式后缓存会清理。state/密钥备份不备份派生订阅缓存。

订阅档案的筛选字段包括 `instanceIds`、`machineUuids`、`excludeMachineUuids`、`protocols`、`includeTags`、`addressMode`、`sortBy` 和 `excludeUnhealthy`。机器/协议空列表按不限制处理；标签按任一实例标签命中。地址模式支持 `auto`、`ipv4`、`ipv6`、`dual`；IPv4/IPv6 只筛选 Endpoint 中的字面 IP，域名留给订阅客户端解析。排序支持节点名称、协议、Endpoint 和机器名称。

## Schema 2 约束

运行时执行的结构检查在 [store.js](../kns/store.js) 中：顶层必须是对象，`schemaVersion` 必须是受支持的正整数，机器、runtime、instance、job、profile、audit、legacyNodes 必须是数组；缺失设置会由默认值补齐。Schema 1 会在内存中逐版本迁移到 Schema 2；首次成功写入时才持久化新结构。下面的 JSON Schema 用于文档与审查，不会取代运行时检查。

Schema 2 的 `setupComplete` 控制首次配置写操作门禁。首次配置同步探针后记录 `autoProvisionBaselineUuids`，基线机器不会被误认为新探针。`autoProvisionNewProbes` 对新安装默认关闭；Schema 1 缺少该字段时迁移为关闭。`defaultNode` 保存仅用于后续新探针的 VLESS + Reality 默认端口/监听地址及模板版本。任务记录可选的 `batchId`、`retryOfJobId`、私有 `retryIdempotencyKey` 和不含凭据的 `retrySpec`，用于受限安全重试与批次恢复；公开状态不会返回这些内部重试参数。

实例的 `remoteStatus.checkedAt`、`resources` 和 `uninstallPreview` 来自最近一次真实 OneBox 状态核查。`uninstallPreview.version` 是 KNS 对目标实例、资源清单和核查时刻生成的 SHA-256 摘要；卸载必须回传匹配摘要，且摘要不得超过五分钟。缺少、过期或不匹配的预览会被服务端拒绝。

实例保存明文 `credential` 对象；旧版 `credentialCiphertext` 在可解密时迁移为明文，无法解密时保留并跳过该节点。旧版 OneBox URI 保存为明文 `uri`。state 文件权限为 `0600`。`KNS_MASTER_KEY`/`kns/master.key` 仅用于兼容旧密文和口令加密导出。每个订阅档案含 `tokens[]`；每个档案只保留一个有效令牌；令牌记录有 `id`、创建/到期/撤销时间、访问计数、最近使用时间及随机 `salt` 和 `hash`；轮换后旧令牌立即失效。为支持管理员重复查看，档案还保存明文 `token`；state 权限为 `0600`。旧版档案的顶层 `salt`/`hash` 会在首次写入时迁移到 `tokens[]`。回调 token 的 hash/salt 仅在任务等待回调期间暂存，第一次有效回调后删除。

管理 API 只返回令牌的非敏感生命周期字段，不返回 `salt`、`hash` 或 token 原文。访问计数按分钟批量写入，进程异常终止最多损失一个周期的未提交计数。令牌到期时间被档案到期时间限制。档案最多保留 50 条令牌记录，撤销记录不会被静默删除。

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Komari KNS state v2",
  "type": "object",
  "required": ["schemaVersion", "revision", "settings", "machines", "runtimes", "instances", "jobs", "profiles", "audit", "legacyNodes"],
  "properties": {
    "schemaVersion": { "const": 2 },
    "pluginVersion": { "type": "string" },
    "revision": { "type": "integer", "minimum": 0 },
    "settings": { "type": "object" },
    "machines": { "type": "array", "items": { "type": "object", "required": ["uuid", "policy"] } },
    "runtimes": { "type": "array", "items": { "type": "object", "required": ["machineUuid", "id", "engine", "references"] } },
    "instances": { "type": "array", "items": { "type": "object", "required": ["id", "machineUuid", "protocol", "listen", "enabled", "publish"] } },
    "jobs": { "type": "array", "items": { "type": "object", "required": ["id", "action", "state", "machineUuid", "idempotencyKey"] } },
    "profiles": { "type": "array", "items": { "type": "object", "required": ["id", "tokens", "formats"], "properties": { "tokens": { "type": "array", "items": { "type": "object", "required": ["id", "salt", "hash", "createdAt", "accessCount"] } }, "machineUuids": { "type": ["array", "null"], "items": { "type": "string", "format": "uuid" } }, "excludeMachineUuids": { "type": "array", "items": { "type": "string", "format": "uuid" } }, "protocols": { "type": ["array", "null"], "items": { "enum": ["vless", "trojan", "vmess", "shadowsocks", "hysteria2", "tuic", "anytls"] } }, "includeTags": { "type": "array", "items": { "type": "string", "maxLength": 32 } }, "addressMode": { "enum": ["auto", "ipv4", "ipv6", "dual"] }, "sortBy": { "enum": ["name", "protocol", "endpoint", "machine"] }, "excludeUnhealthy": { "type": "boolean" } } } },
    "audit": { "type": "array" },
    "legacyNodes": { "type": "array" }
  },
  "additionalProperties": true
}
```

## 备份策略

- 每日首次状态更新前创建一份状态 JSON 备份；若存在 master key，同时复制当日 key，但明文 state 的恢复不依赖该 key。
- 只保留最近 7 天的 state/key 备份。
- 每 5 分钟或审计事件后写一次状态快照，最多保留 288 份（约 24 小时）。
- 审计事件追加写入独立日志，不随 state restore/import 覆盖；保留最近 365 天且总量上限 16 MiB、单段 256 KiB。超过期限或容量时先写清理检查点，再删除最旧日志段；管理 API/UI 显示清理数量与时间范围。若清理中断，下次读取/追加先完成带检查点的操作。
- `backup.restore` 恢复状态与匹配日期的 key，并在覆盖前复制当前状态到 `pre-restore-*`。
- 管理员导出为独立口令加密包（PBKDF2-SHA256 + AES-256-GCM），其中包含 state 与恢复所需 master key；管理页可导入该包，并在写入前保留 `pre-import-*` 副本。若宿主注入 `KNS_MASTER_KEY`，仅允许导入匹配密钥的备份；丢失口令无法解密。审计日志以独立目录保留，不包含在 state/key 加密导出包中，搬迁服务时需另行安全复制 `kns/audit/`。插件 ZIP/SBOM 不包括用户运行状态。

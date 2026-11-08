# 数据模型与状态 Schema

插件状态保存于 Komari 提供的 `__storageDir__` 下的 `kns/state.json`。目录、状态、备份、快照和密钥文件权限设为 `0700/0600`（宿主文件系统支持时）。状态写入使用同目录临时文件和原子 rename。未知字段会保留，当前 schema 版本为 `1`。

## 顶层对象

| 字段 | 说明 |
| --- | --- |
| `schemaVersion`, `revision`, `createdAt`, `updatedAt` | 版本和递增修订信息 |
| `settings` | HTTPS 回调基地址、SubConverter、固定 OneBox installer SHA、健康/同步间隔、私有站点开关、批量上限 |
| `machines[]` | Komari Agent 探针快照及管理员部署/地址策略 |
| `runtimes[]` | 每台机器上的共享 OneBox `sing-box/onebox-main` 服务引用计数 |
| `instances[]` | 由 KNS 管理的远端实例，保存监听、端点、协议元数据、发布/健康状态和加密凭据 |
| `jobs[]` | 授权、远程任务编号、回调摘要、结果核验与审计关联；不存远程 stdout/stderr |
| `profiles[]` | 订阅格式、过滤条件、档案过期时间及 `tokens[]` 生命周期记录 |
| `audit[]` | 管理动作摘要；不记录订阅 token 或节点凭据 |
| `legacyNodes[]` | 从原 onebox-bridge 数据迁移的加密 URI |
| `lastSnapshotAt`, `snapshotPending` | 周期/事件快照标记 |

订阅正文缓存与 state 备份快照分开保存于 `kns/subscriptions/<sha256(profileId,format)>.json`。文件只包含 AES-256-GCM 密文 envelope；明文正文仅在构建/服务期间驻留内存。完整密文写入权限为 `0600` 的临时文件后原子替换，缓存记录包含内容 SHA-256、生成时间、规则版本、成功数、跳过数和来源哈希。成功数按输出条目计数（URI 行或配置节点），跳过数按未输出的已发布实例计数。档案/实例状态变化会触发事件刷新，每 5 分钟兜底；订阅 GET 不调用生成器，并会校验本地来源哈希。状态已变化而快照尚未更新时返回 `503 Retry-After: 2`，避免继续发布旧节点；档案撤销、过期或移除格式后缓存会清理。缓存丢失时可从 state 与匹配密钥重建；缓存或凭据因密钥不匹配无法解密时维持 `503`，需要恢复配对的 state/key 备份。state/密钥备份不备份派生订阅缓存。

订阅档案的筛选字段包括 `instanceIds`、`machineUuids`、`excludeMachineUuids`、`protocols`、`includeTags`、`addressMode`、`sortBy` 和 `excludeUnhealthy`。机器/协议空列表按不限制处理；标签按任一实例标签命中。地址模式支持 `auto`、`ipv4`、`ipv6`、`dual`；IPv4/IPv6 只筛选 Endpoint 中的字面 IP，域名留给订阅客户端解析。排序支持节点名称、协议、Endpoint 和机器名称。

## Schema 1 约束

运行时执行的结构检查在 [store.js](../kns/store.js) 中：顶层必须是对象，`schemaVersion` 必须是受支持的正整数，机器、runtime、instance、job、profile、audit、legacyNodes 必须是数组；缺失设置会由默认值补齐。下面的 JSON Schema 用于文档与审查，不会取代运行时检查。

凭据不以内嵌明文字段保存。实例保存 `credentialCiphertext`（AES-256-GCM envelope）；密钥来自环境变量 `KNS_MASTER_KEY`（64 位十六进制）或 `kns/master.key`。每个订阅档案含 `tokens[]`；每条令牌记录有 `id`、创建/到期/撤销/轮换宽限时间、访问计数、最近使用时间及随机 `salt` 和 `hash`，不存原始 token。旧版档案的顶层 `salt`/`hash` 会在首次写入时迁移到 `tokens[]`。回调 token 的 hash/salt 仅在任务等待回调期间暂存，第一次有效回调后删除。

管理 API 只返回令牌的非敏感生命周期字段，不返回 `salt`、`hash` 或 token 原文。访问计数按分钟批量写入，进程异常终止最多损失一个周期的未提交计数。令牌到期时间被档案到期时间限制。档案最多保留 50 条令牌记录，撤销记录不会被静默删除。

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Komari KNS state v1",
  "type": "object",
  "required": ["schemaVersion", "revision", "settings", "machines", "runtimes", "instances", "jobs", "profiles", "audit", "legacyNodes"],
  "properties": {
    "schemaVersion": { "const": 1 },
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

- 每日首次状态更新前创建一份状态 JSON 备份；若存在 master key，同时复制当日 key。
- 只保留最近 7 天的 state/key 备份。
- 每 5 分钟或审计事件后写一次状态快照，最多保留 288 份（约 24 小时）。
- `backup.restore` 恢复状态与匹配日期的 key，并在覆盖前复制当前状态到 `pre-restore-*`。
- 管理员导出为独立口令加密包（PBKDF2-SHA256 + AES-256-GCM），其中包含 state 与恢复所需 master key；管理页可导入该包，并在写入前保留 `pre-import-*` 副本。若宿主注入 `KNS_MASTER_KEY`，仅允许导入匹配密钥的备份；丢失口令无法解密。插件 ZIP/SBOM 不包括用户运行状态。

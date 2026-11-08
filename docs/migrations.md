# 状态迁移

## 原型 `onebox-bridge.json` 到 KNS Schema 1

首次加载时，如果 `kns/state.json` 不存在而旧版 `onebox-bridge.json` 存在，插件先把 `__storageDir__` 的现有内容复制到 `kns/backups/pre-migration-*`，再在内存中读取旧文件并迁移。快照包含已有状态、master key、订阅快照、旧文件及同目录其他数据；新文件按 `0600`、目录按 `0700` 保存。为避免重试时递归复制快照，备份会排除已有的 `pre-migration-*` 和 `pre-upgrade-*` 回滚点。若快照失败，插件停止迁移，旧 JSON 不删除或重写；如果目录发布失败，备份暂存副本会保留在 `__storageDir__` 同级供恢复。迁移写入采用临时文件加原子替换：

1. 复制旧 SubConverter URL 与 `clash`/`singbox` target（仅接受支持的值）。
2. 将旧订阅 token 转为 KNS salted hash/salt，创建 `legacy-default` 档案；旧 token 继续用于旧 `/api/onebox-bridge/subscribe` 兼容路由。
3. 将旧记录映射成机器占位和 `legacyNodes[]`，旧 URI 以当前 master key 加密。
4. 写入 `state.json` 并增加 `state.migrated` 审计条目；原 `onebox-bridge.json` 保留，不删除。

若旧 JSON 损坏，插件拒绝覆盖并返回 `legacy_state_corrupt`。先从宿主备份恢复旧 JSON，再重启插件。迁移快照可能包含凭据与令牌，应作为敏感数据保管；它不会自动清理。

## OneBox 历史安装节点

管理页的“扫描旧版节点”通过固定 SHA-256 的临时适配器只读解析 `/etc/onebox/config.json`；发现结果仅含安全元数据，不含认证字段。支持的单用户 VLESS Reality、Hysteria2、TUIC、AnyTLS 和 Shadowsocks 可由管理员逐个确认导入；适配器经一次性 HTTPS 回调提交凭据，KNS 加密保存。导入只创建 KNS 外部只读实例记录，不修改 OneBox inbound、证书、防火墙或服务。多用户、VLESS WS/Argo、缺少凭据/Reality 公钥/SNI、非通配监听地址等节点保持未导入状态。

## 插件升级备份

每次插件版本与 state 中记录的 `pluginVersion` 不同，或此前没有版本标记时，读取状态后、注册路由前先复制 `__storageDir__` 现有内容到 `kns/backups/pre-upgrade-*`，成功后才写入新版本标记。备份失败或 state 来自更新版本时停止插件加载，不写入状态。插件状态 schema 仍为 1；已发布的早期 KNS 版本也使用 schema 1，因此当前插件二进制升级不需要字段迁移。未来提升 `schemaVersion` 前，必须增加逐版本迁移函数和相应回滚测试。

## Schema 版本

当前只实现 Schema 1。读到更高版本或非法版本时会失败并保留原文件，不做破坏性重置。当前 Schema 1 内部补齐缺失默认字段，但尚无 Schema 2 迁移函数。

## 升级和回退要求

- 升级前从管理页导出加密状态包，并将独立口令与文件分开保管；日常恢复使用 state/key 文件时也应单独保管 `master.key`/`KNS_MASTER_KEY`。
- 回退插件包时保留 `kns/` 数据目录；不要用旧插件覆盖或删除新状态。
- 如果旧版本不认识 KNS Schema 1，不要启动它读取新状态目录；先恢复与旧插件匹配的状态备份。
- 丢失 master key 会使加密实例凭据与迁移 URI 无法解密；恢复时必须使用和 state 备份同日的 key。

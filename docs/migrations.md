# 状态迁移

## 原型 `onebox-bridge.json` 到 KNS Schema 1

首次加载时，如果 `kns/state.json` 不存在而旧版 `onebox-bridge.json` 存在，插件会在内存中读取旧文件并迁移：

1. 复制旧 SubConverter URL 与 `clash`/`singbox` target（仅接受支持的值）。
2. 将旧订阅 token 转为 KNS salted hash/salt，创建 `legacy-default` 档案；旧 token 继续用于旧 `/api/onebox-bridge/subscribe` 兼容路由。
3. 将旧记录映射成机器占位和 `legacyNodes[]`，旧 URI 以当前 master key 加密。
4. 写入 `state.json` 并增加 `state.migrated` 审计条目；原 `onebox-bridge.json` 保留，不删除。

若旧 JSON 损坏，插件拒绝覆盖并返回 `legacy_state_corrupt`。先从宿主备份恢复旧 JSON，再重启插件。

## Schema 版本

当前只实现 Schema 1。读到更高版本或非法版本时会失败并保留原文件，不做破坏性重置。当前 Schema 1 内部补齐缺失默认字段，但尚无 Schema 2 迁移函数。

## 升级和回退要求

- 升级前从管理页导出加密状态包，并将独立口令与文件分开保管；日常恢复使用 state/key 文件时也应单独保管 `master.key`/`KNS_MASTER_KEY`。
- 回退插件包时保留 `kns/` 数据目录；不要用旧插件覆盖或删除新状态。
- 如果旧版本不认识 KNS Schema 1，不要启动它读取新状态目录；先恢复与旧插件匹配的状态备份。
- 丢失 master key 会使加密实例凭据与迁移 URI 无法解密；恢复时必须使用和 state 备份同日的 key。

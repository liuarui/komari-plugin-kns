# 状态迁移

## 原型 `onebox-bridge.json` 到 KNS Schema 1

首次加载时，如果 `kns/state.json` 不存在而旧版 `onebox-bridge.json` 存在，插件先把 `__storageDir__` 的现有内容复制到 `kns/backups/pre-migration-*`，再在内存中读取旧文件并迁移。快照包含已有状态、master key、订阅快照、旧文件及同目录其他数据；新文件按 `0600`、目录按 `0700` 保存。为避免重试时递归复制快照，备份会排除当前暂存目录及已有的 `pre-migration-*` 和 `pre-upgrade-*` 回滚点。暂存目录保留在 `__storageDir__` 内，以符合 Komari 文件系统授权范围；发布失败时会尝试清理未完成副本，原始数据不变。迁移写入采用临时文件加原子替换：

1. 复制旧 SubConverter URL 与仍在支持列表内的 `converterTarget`（Clash、ClashR、Surge、Quantumult、Quantumult X、Loon、Surfboard、Stash、Mellow、sing-box、SS、SSD、SSR、SSSub、V2Ray、V2RayN、V2RayNG、Shadowrocket、Trojan、VLESS、Hysteria2、Mixed）。
2. 将旧订阅 token 转为 KNS salted hash/salt，创建 `legacy-default` 档案；旧 token 继续用于旧 `/api/onebox-bridge/subscribe` 兼容路由。
3. 将旧记录映射成机器占位和 `legacyNodes[]`，旧 URI 以当前 master key 加密。
4. 写入 `state.json` 并增加 `state.migrated` 审计条目；原 `onebox-bridge.json` 保留，不删除。

若旧 JSON 损坏，插件拒绝覆盖并返回 `legacy_state_corrupt`。先从宿主备份恢复旧 JSON，再重启插件。迁移快照可能包含凭据与令牌，应作为敏感数据保管；它不会自动清理。

## OneBox 历史安装节点

管理页可批量勾选在线探针并提交最多 100 台的只读扫描（最多 5 个同时提交请求），也可单机扫描。固定 SHA-256 的 OneBox 适配器只读解析其可识别的 `/etc/onebox/config.json`；发现结果仅含安全元数据，不含认证字段。它不枚举任意代理程序或 OneBox 自定义路径。支持的单用户 VLESS Reality、Hysteria2、TUIC、AnyTLS 和 Shadowsocks 会在机器卡片中显示“纳入管理并加入订阅”操作；按钮点击即提交导入，适配器经一次性 HTTPS 回调提交凭据，KNS 加密保存。导入只创建 KNS 外部只读实例记录，不修改 OneBox inbound、证书、防火墙或服务。多用户、VLESS WS/Argo、缺少凭据/Reality 公钥/SNI、非通配监听地址等节点保持未导入状态。

## 插件升级备份

每次插件版本与 state 中记录的 `pluginVersion` 不同，或此前没有版本标记时，读取状态后、注册路由前先复制 `__storageDir__` 现有内容到 `kns/backups/pre-upgrade-*`，成功后才写入新版本标记。暂存目录直接创建在 `__storageDir__` 内，并在复制时排除自身，以适配 Komari 的受限文件系统。备份失败或 state 来自更新版本时停止插件加载，不写入状态；升级错误会显示截断清理后的底层原因。

## Schema 版本

当前 Schema 为 2。Schema 1 迁移在读取时为旧状态补齐 `setupComplete`、`autoProvisionNewProbes`、自动部署基线和默认节点模板：已有 `pluginVersion` 或 HTTPS 回调地址的旧安装视为已初始化；旧版没有自动部署字段时始终默认为关闭。机器远程安装权限默认开启：升级时会先备份存储，再一次性为已有机器启用该权限；新同步的机器也默认开启，管理员之后仍可逐台关闭。该权限只允许管理员提交远程安装任务，不会自行安装；新探针自动部署仍默认关闭。Schema 1 中若确有布尔自动部署值则保留该值。读到更高版本或非法版本时会失败并保留原文件，不做破坏性重置。

## 升级和回退要求

- 升级前从管理页导出加密状态包，并将独立口令与文件分开保管；日常恢复使用 state/key 文件时也应单独保管 `master.key`/`KNS_MASTER_KEY`。
- 回退插件包时保留 `kns/` 数据目录；不要用旧插件覆盖或删除新状态。
- 如果旧版本不认识 KNS Schema 2，不要启动它读取新状态目录；先恢复与旧插件匹配的状态备份。
- 丢失 master key 会使加密实例凭据与迁移 URI 无法解密；恢复时必须使用和 state 备份同日的 key。

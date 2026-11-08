# 运维手册

## 运行结构

Komari 插件注册路由和 cron，不在 Komari 主机启动自己的服务。每个远端机器上 KNS 管理一个共享 `onebox-main` sing-box Runtime 和实例清单。KNS 仅通过 `admin:exec` 下发命令，再通过 Agent task result 与 OneBox HTTPS 回调核验。管理页状态读取不会触发机器同步或远端操作。

## 定时任务

| 周期 | 工作 |
| --- | --- |
| 15 秒 | 查询最多 20 个等待中的 Agent 任务 |
| 1 分钟 | 同步 Komari 探针清单，再解析稳定 DDNS 和核验变更端点 |
| 5 分钟 | TCP/标准 TLS 健康探测，最多同时 5 个实例 |
| 每日 03:00 | 触发状态保存；实际日备份在首次状态写入时创建 |

健康策略：3 次连续失败标记 `unhealthy`，2 次连续成功标记 `healthy`；中间状态为 `suspect`。Reality 探测只做 TCP，不执行 Reality 握手。UDP/QUIC 只报告 Agent/OneBox listener 状态并标为 `unverified`。

## 备份与恢复

管理页可创建或导入口令加密的离线备份，也可通过 `backup.restore` 恢复每日备份。日常滚动备份中的 `kns/master.key` 或注入的 `KNS_MASTER_KEY` 必须与状态日期严格匹配。导入会保留 `pre-import-*` state/key；每日恢复会保留 `pre-restore-*` state。操作步骤见 [回滚演练](rollback-drill.md)。

## 日志与故障定位

1. 在任务页确认 job 状态、Agent UUID、OneBox 适配器版本、退出码和错误码。
2. 在 Komari 探针页核对 Agent 在线、远程控制权限和 Agent root 身份。
3. 在目标机运行 `onebox kns status --instance-id <id>`，比较 OneBox manifest、入站和 systemd/OpenRC 服务状态。
4. 从目标机检查 HTTPS 回调是否能访问 `publicBaseUrl + /api/kns/report`。
5. 检查本机防火墙、云安全组、NAT 映射、域名 A/AAAA、端口监听和证书/SNI。
6. 对 `needs_reconcile` 任务先执行状态核查，不要立即重装。

插件不持久化 Agent 输出全文。需要诊断细节时，应在目标机本地受控查看 OneBox 安装器日志，避免把节点密码或 subscription URI 粘贴到 Komari 日志。

## 更新与卸载

更新时在 Komari 中上传新 ZIP；保持插件 `short` 不变，数据沿用同一 storage directory。卸载前通过 UI 分别卸载 KNS 管理的实例；此操作不会卸载共享 OneBox 服务。然后导出 state 与 key，再禁用/移除插件。删除插件 storage 会丢失档案、审计、备份以及解密凭据所需 key。

## 运行限制

- 最多 5 个健康/地址 TCP 探测并发；远程动作按每台机器共享 runtime 串行。
- 批量 UI 提交最多 10 个探针。
- HTTP SubConverter URL 可用于内网试用，但订阅 token 和节点凭据会以明文传输；公网分发前应给 Komari 和 SubConverter 配置 HTTPS。
- 私有 Endpoint 只应在管理员能控制的私网环境使用；该模式的真实部署/访问控制未在目标 Komari 私有站点上验收。

# 运维手册

## 运行结构

Komari 插件注册路由和 cron，不在 Komari 主机启动自己的服务。每个远端机器上 KNS 管理一个共享 `onebox-main` sing-box Runtime 和实例清单。KNS 仅通过 `admin:exec` 下发命令，再通过 Agent task result 与 OneBox HTTPS 回调核验。管理页状态读取不会触发机器同步或远端操作；管理员可手动触发旧节点只读扫描，扫描结果中的“纳入管理并加入订阅”按钮用于提交凭据导入。

## 定时任务

| 周期 | 工作 |
| --- | --- |
| 15 秒 | 查询最多 20 个等待中的 Agent 任务 |
| 15 秒 | 同步 Komari 探针清单 |
| 1 分钟 | 解析稳定 DDNS 和核验变更端点 |
| 5 分钟 | TCP/标准 TLS 健康探测，最多同时 5 个实例 |
| 每日 03:00 | 触发状态保存；实际日备份在首次状态写入时创建 |

健康策略：3 次连续失败标记 `unhealthy`，2 次连续成功标记 `healthy`；中间状态为 `suspect`。Reality 探测只做 TCP，不执行 Reality 握手。UDP/QUIC 只报告 Agent/OneBox listener 状态并标为 `unverified`。

## 备份与恢复

管理页可创建或导入口令加密的离线备份，也可通过 `backup.restore` 恢复每日备份。明文 state 的日常恢复不再依赖 `kns/master.key`；仅旧版密文字段仍需要匹配的 key。使用 `KNS_MASTER_KEY` 时，恢复会检查备份密钥（若存在）与注入密钥是否一致。仅当备份中仍含旧版密文字段时才需要配套密钥；明文 state 的每日备份不需要 key。恢复前保留 `pre-restore-*` state/key，并写入事务日志；插件重启若发现中断恢复，会在读取状态前回滚到恢复前的 state/key。操作步骤见 [回滚演练](rollback-drill.md)。

## 日志与故障定位

1. 在目标机器卡片的“最近操作”或“操作记录”页查看 job 状态、Agent UUID、OneBox 适配器版本、退出码和错误码。
2. 在 Komari 探针页核对 Agent 在线、远程控制权限和 Agent root 身份。
3. 在目标机运行 `onebox kns status --instance-id <id>`，比较 OneBox manifest、入站和 systemd/OpenRC 服务状态。
4. 从目标机检查 HTTPS 回调是否能访问 `publicBaseUrl + /api/kns/report`。
5. 检查本机防火墙、云安全组、NAT 映射、域名 A/AAAA、端口监听和证书/SNI。
6. 对 `needs_reconcile` 任务先执行状态核查，不要立即重装。

插件不持久化 Agent 输出全文。需要诊断细节时，应在目标机本地受控查看 OneBox 安装器日志，避免把节点密码或 subscription URI 粘贴到 Komari 日志。

审计事件追加写入 `kns/audit/`，与可回滚的状态 JSON 分开保存。保留最近 365 天且最多 16 MiB；达到期限或空间上限时先落清理检查点，再清理最旧日志段。管理页显示清理条数和覆盖时间。复制服务或恢复 state 时，需另外备份/迁移该目录；带检查点的保留清理不会随 state restore 回滚。

## OneBox 升级、插件更新与卸载

机器卡片的“机器设置与维护”中提供两个独立操作：“更新 OneBox 管理工具”只替换固定 SHA-256 核验过的管理脚本，不改节点配置或重启服务；“升级 sing-box 内核”会影响该机全部节点，短暂重启共享服务，并保持原先 active/inactive 状态。两项都要求机器在线、已授权安装、最近 30 分钟内完成 OneBox 只读扫描、已配置公网 HTTPS 回调且没有同机活动任务。页面显示真实 Agent 任务和回调/版本核验结果；`needs_reconcile` 时先重新核查状态，不要重复升级。

在设置页点击“检查更新”，发现新版本后可确认安装：KNS 从官方 GitHub Release 下载并核对 SHA-256，浏览器通过 Komari 的插件上传接口安装，插件会短暂重启。存在未完成远程任务时不能更新。若安装结果不明确，在 Komari 插件管理中核对，必要时手动上传发布页 ZIP；旧版本首次升级到支持此功能的版本也需手动上传。保持插件 `short` 不变，数据沿用同一 storage directory。卸载前通过 UI 分别卸载 KNS 管理的实例；此操作不会卸载共享 OneBox 服务。然后导出 state 与 key，再禁用/移除插件。删除插件 storage 会丢失档案、审计、备份以及解密凭据所需 key。

## 运行限制

- 最多 5 个健康/地址 TCP 探测并发，这些网络探测运行在 Komari 服务器，不会在目标 LXC 启动对应进程。KNS 对同一探针的 OneBox 远程任务（含状态核查、发现、导入、节点配置及 OneBox 管理脚本/内核升级）串行；任务未完成时后续请求返回 `runtime_busy`。
- OneBox 对低 PID/内存余量做分操作预检：只读发现/列表至少 3 个可见 PID 和 8 MiB 内存；旧节点导入至少 5 个 PID 和 32 MiB；节点安装、配置变更、启停、接管、卸载及管理脚本更新至少 8 个 PID 和 32 MiB；sing-box 内核更新至少 8 个 PID 和 64 MiB。首次初始化和依赖安装仍要求 64 MiB。内存不足时任务显示实测可用量及本次门槛。Reality SNI 扫描按可见额度降为串行。Linux cgroup 的 `pids.current` 统计内核 task，包含线程；例如 `pids.max=20` 时，Agent、sing-box 及其他容器进程/线程已占用的名额都要从 20 中扣除。预检是启动前的采样门槛，不能为任务预留名额，也无法控制其他进程抢占或检测未暴露给容器的宿主机限制，因此 20–30 的总额度不等于保证可安装；安装/变更需至少 8 个可见余量。
- 安装向导一次最多选择 10 台机器。多协议会按顺序提交，并等待当前协议所有机器通过真实任务核验后再继续；此多协议计划由当前页面串行驱动，页面关闭或离开后尚未提交的协议不会自动续跑。机器页可逐台或批量只读扫描旧版节点，也可一键扫描在线且未标记为“不纳管”的机器并顺序接管受支持节点。批量接管按机器地址策略及监听端口生成订阅；NAT 外部端口需事先单独处理，关闭页面后未提交的任务不会继续。所有远程命令派发前重新检查在线状态，无法确认在线时不发送；连接仍可能在检查后断开。
- 管理 API 写请求接受同源浏览器 Origin、与管理员配置的 HTTPS 公网 URL Origin 完全匹配的请求，或 HTTPS 请求中浏览器标记为 `Sec-Fetch-Site: same-origin` 的请求，以兼容反向代理改写上游 Host；插件不信任任意客户端提供的 `X-Forwarded-Host`。跨站 Origin 仍会拒绝。在线状态经 Komari `common:getNodesLatestStatus` RPC 与客户端基础记录合并。
- 外部 SubConverter 默认关闭，须显式配置受信 HTTPS `/sub` 地址才能生成转换链接；不支持 HTTP（包括内网）。已有 HTTP 配置也不会生成转换链接。清空地址并保存可关闭转换，KNS 原生订阅不受影响。
- 私有 Endpoint 只应在管理员能控制的私网环境使用；该模式的真实部署/访问控制未在目标 Komari 私有站点上验收。

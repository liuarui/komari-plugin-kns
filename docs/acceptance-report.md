# 验收测试报告

日期：2026-11-08（工作区日期）。本报告区分本地模拟/静态检查与目标环境实测。交互整改 UX 1.0 的 40 条记录按其 §17 逐项列于 `docs/ux-acceptance-t40.md`；下方 AT-01 至 AT-32 是 v1.1.5 既有 OneBox/Komari 目标环境验收记录，不与本轮 UI 模拟混为一谈。

## v1.2.2 在线状态与反代兼容回归

本地 `node --test tests/*.test.js`：26 项通过，0 失败。新增覆盖 Komari `common:getNodesLatestStatus` 在线状态合并、反代改写上游 Host 时的 `Sec-Fetch-Site: same-origin` 写入，以及跨站/缺少 Origin/HTTP 来源仍被拒绝。运行时 JavaScript 语法检查、ZIP CRC 和 SHA-256 均通过；`dist/onebox-bridge.zip` SHA-256 为 `ebc777d47b373b1aa3a0ae27c115ae2da5bf4c4df0ccf27410f9be3ee7fb4d64`。

目标后台在本轮只读查看到 Komari Server `1.6.1 (96cf0f7)`、插件管理页的 KNS `1.2.1`。Komari 仪表板当时显示 `0/31` 在线；KNS 1.2.1 仍将目标“free 月抛三网”显示为“未知”，因此定位出在线 RPC 调用缺少 `common:` 命名空间。1.2.2 已修正并打包，但因 Mac 锁屏，尚未上传 1.2.2、保存 KNS HTTPS 公网地址或发起目标只读扫描。未派发 OneBox 远程任务，也未更改探针。

## v1.2.0 交互整改回归

本轮执行 `node --test tests/*.test.js`：26 项测试通过，0 失败。覆盖首次初始化门禁、Schema 1 迁移、revision 冲突、订阅与状态逻辑、批次幂等、有限任务重试的同键复用/异键拒绝/禁止链式重试、服务端卸载预览版本不匹配拒绝，以及 state/key 备份恢复。脚本语法、管理页内嵌 JavaScript、manifest/schema/依赖锁 JSON 检查通过；管理页未发现原生 `prompt()` 或 `confirm()` 调用。

UX 1.0 的 40 条记录见 `docs/ux-acceptance-t40.md`。其中本地模拟与源码实现按实际范围说明；浏览器视觉、键盘、响应式和真实 Komari/Agent/客户端验收仍未执行。没有可用的授权目标环境或脱敏浏览器会话，未生成截图/录屏，也不把未执行用例标为通过。

## 本地可复现命令

```sh
node --test tests/*.test.js
node --check script.js
node --check kns/index.js
node --check kns/subscription.js
bash -n /Users/ajax/Documents/MyProject/onebox/install.sh  # OneBox sibling checkout; adjust this path
python3 -m py_compile scripts/package.py
python3 scripts/package.py
```

以下 24 项 Node 测试范围和旧 Komari 复测记录属于 v1.1.5 历史基线，不代表 v1.2.0 当前测试结果：模拟 admin policy、agent task、OneBox callback/status、同探针远程任务互斥、历史节点只读发现/导入与外部只读策略、资源余量失败提示、旧节点凭据进入加密订阅但不进入快照明文；profile 只返回启用格式的链接并为受支持 SubConverter target 生成 URL；代理改写 Host 时只接受配置的公网 Origin，拒绝不匹配来源和同主机 HTTP 降级 Origin；Komari 兼容 fs 缺失 master key 时 `lstat` 错误的初始化回归；无全局 URL 构造器时 `node:url` 回退；迁移前私有存储目录快照；插件版本升级前快照和降级拒绝；模拟 Komari 仅允许访问 `__storageDir__` 时，验证升级备份文件操作留在授权根目录，且发布失败后原 state 不变并清理暂存副本；state/key 每日备份配对、备份中断重试和恢复失败回滚；追加审计日志、保留检查点、清理中断恢复和 state restore 后日志连续性；secret 加密与 token hash；多令牌创建、独立撤销、宽限轮换、使用计数与档案有效期上限；口令加密导出往返解密；NAT 公网映射冲突拒绝；加密订阅快照的私有文件写入、替换失败清理、权限、修剪及 GET 只读快照；IPv6 URI 编码；七协议格式生成；机器/协议/标签/地址族筛选、排序与连接去重；profile 筛选字段创建和更新。OneBox 低 PID/内存 guard 与五种旧协议发现另用临时 JSON 夹具做函数级模拟；这些本地模拟都不代表真实机器/客户端验收。批量旧节点扫描复用已测的单机 `machine.discover` 路由；多机 UI 选择及并发提交尚无浏览器自动化/目标服务实测。

## v1.1.5 历史：目标 Komari 初始化复测

用户管理后台此前显示 Komari Server `1.6.1 (96cf0f7)`。首次启用先前 ZIP 时，宿主对缺失的 `kns/master.key` 路径报 `lstat ... no such file or directory`，插件未能启用。v1.1.2 已改为先用 Komari 支持的 `existsSync` 检查，再通过排他文件打开生成 32 字节 key，并同步写入；v1.1.3 保留该修复，并另修复反代环境下的管理 Origin 比对。之后 v1.1.3 加载时因备份暂存目录建在 `__storageDir__` 的父目录、超出 Komari 授权范围而失败；v1.1.4 将暂存目录移入授权根内，并返回底层原因。本地受限文件系统回归用例通过。用户最近再次提供的错误文本与 v1.1.3 的通用错误字符串完全相同；v1.1.4/1.1.5 会额外显示“原因：…”。面板页面本次读取超时，无法确认服务器当前安装版本；未上传新包。v1.1.5 另固定 OneBox adapter 1.4.0、修复 VLESS Reality 请求缺失 SNI，并将完整审计日志独立于可恢复状态保存。目标面板启动仍待上传复测。

## v1.1.5 历史：AT-01 至 AT-32

| AT | 场景 | 当前结果 | 证据/缺口 |
| --- | --- | --- | --- |
| 01 | 新探针出现在列表且 UUID 稳定 | 部分本地模拟 | mock `admin:listClients` 单次列表包含 UUID；重查/重启后的稳定性未断言，未接目标 Komari |
| 02 | 未授权机器不执行安装 | 本地自动测试通过 | 设置 `deployAllowed:false` 后安装请求返回 `deployment_not_allowed`，mock `admin:exec` 未调用；未接目标 Agent |
| 03 | 同机多协议实例 | 部分实现 | 七协议格式生成；未在同机安装多协议 |
| 04 | 幂等重试不重复 | 静态实现；测试未覆盖 | 代码有按 idempotency key 复用/冲突检查；现有测试未以相同 key 重放或冲突 payload，未做 OneBox 重复安装真机测试 |
| 05 | 卸载一个节点不影响共享 runtime | status 字段单测；UI/真机阻断 | mock status 的资源归属、共享引用数和服务影响字段进入 state；5 分钟预览时效、确认流程未做浏览器测试，仍需同机多实例真机卸载与连通性证据 |
| 06 | 全部 KNS 实例移除不影响非托管服务 | **待真机** | 需目标机现有非 KNS inbound 基线与卸载后验证 |
| 07 | 卸载中途失败自动回滚并留审计 | **阻断：待故障注入** | 事务/回滚实现；未在目标机注入失败 |
| 08 | 手动隐藏实例后从订阅移除 | 本地自动测试 | `publish:false` 将实例隐藏于订阅；旧来源哈希快照暂返 503，刷新后 URI 移除该节点。此项不测试远端 OneBox disable；Agent 真正停用未上真机 |
| 09 | IPv4 变化后 URL 不变且 server 更新 | **阻断：待真机** | profile URL 稳定代码；未制造真实地址变化 |
| 10 | IPv6-only 输出 IPv6 | 部分本地验证 | IPv6 方括号单测；没有 IPv6-only Agent 与客户端 |
| 11 | 双栈输出独立 V4/V6 | 部分本地验证 | IPv4/IPv6 连接去重、地址族过滤有单测；profile `dual` 双地址独立输出未覆盖，未跑真双栈 Agent 与客户端导入 |
| 12 | 手动 IPv4 不被自动同步覆盖 | 静态实现 | 地址优先级实现；未跑动态 IP 实测 |
| 13 | NAT 443→30443 发布外部端口 | 安装冲突本地模拟通过；动态地址保护静态检查；真机待测 | 模拟 install 保存外部端口和公网 host；动态刷新发现映射冲突时会暂停订阅发布，待无冲突且通过连通性核查后恢复；未验证真实 NAT 转发或动态冲突演练 |
| 14 | TCP/UDP 同端口冲突按实际规则处理 | 部分实现 | 插件与 OneBox 冲突规则静态检查；未跑端口占用矩阵 |
| 15 | DDNS 输出域名且变更不破坏 SNI | 部分本地验证 | A/AAAA 两次稳定门控、双栈地址族过滤；未用真实 DDNS/SNI 证书 |
| 16 | TCP 连续失败三次后 unhealthy | 静态实现 | 阈值逻辑；未运行连续探测演练 |
| 17 | 连续成功两次后恢复订阅 | 静态实现 | 阈值与 profile 过滤逻辑；未运行端到端演练 |
| 18 | HY2 未做协议检测时不能标 L3 healthy | 静态实现 | UDP 明确 `unverified`；没有 L3 adapter |
| 19 | Mihomo full/provider 可导入 | 结构断言通过；解析器/客户端待验收 | 本地断言 full/provider 关键字段；没有 YAML parser 校验，也未锁定 Mihomo/OpenClash 版本或实际导入 |
| 20 | URI 客户端导入参数完整 | **待客户端导入** | 生成七协议 URI；客户端及版本未指定 |
| 21 | sing-box JSON 在冻结版校验 | **待冻结版本** | 本地 JSON 解析通过；没有目标 sing-box 二进制 |
| 22 | 连接去重且 IPv4/IPv6 不互相去重 | 本地单元通过 | 等价代理连接合并；不同地址族保留两条 |
| 23 | Token 撤销后立即拒绝订阅 | 本地自动 HTTP 断言通过；目标代理待验收 | 独立 token 撤销后旧 URL 返回 404；profile 整体撤销后返回 403。未在生产 Komari 代理链路上核对状态码 |
| 24 | 非法 token 不能访问机器/其他 Profile | 覆盖有限 | 仅测试错误订阅 token 对既有 profile 的订阅 GET 返回 404；未测试订阅 token 访问管理/机器路由或跨 Profile 隔离 |
| 25 | Komari 重启后状态/任务/订阅恢复 | 静态 + 存储单测 | file state 与待处理 jobs 持久化；未重启 Komari 服务 |
| 26 | 升级保留配置/凭据且能回滚 | **阻断：待目标环境** | 备份/恢复单测；插件升级回滚未演练 |
| 27 | 错误地址/端口/冲突映射拒绝 | 部分本地模拟，真机待测 | 非法 70000 端口和相同公网 host/外部端口/传输映射被拒；无效 IP 与真实监听占用矩阵未覆盖 |
| 28 | Agent 离线/远控关闭给出原因 | 静态实现；目标 Agent 待测 | 错误码映射在源码中；未通过离线 Agent 或关闭远控的自动化/真机测试 |
| 29 | 100 机器订阅 P95 < 1s | **待压测** | 未有目标机规格或压测数据 |
| 30 | 日志无凭据/token/敏感输出 | 本地审查 + 单测 | 状态脱敏、callback hash 消费、无远端全文持久化；未做线上日志审计 |
| 31 | Komari 原插件/监控回归 | **待目标环境** | 已登录目标管理后台并确认 Server 1.6.1；KNS 未能启用，尚未运行安装后监控回归 |
| 32 | private_site 下管理/订阅访问 | **阻断：待真机** | 规格要求在 private_site 实测；未绕过/修改 Komari 核心 |

## 验收结论

代码与本地模拟阶段完成，目标环境验收未完成。规格要求 AT-05、07、09、13、23、26、32 为强制阻断；除 AT-23 的本地自动 HTTP 断言通过外，其余强制项仍需在目标环境取得证据；AT-23 也需核对目标反向代理是否保留 403。至少还需要公网 IPv4、IPv6-only、NAT、双栈和共享 Runtime 环境，冻结 Komari/Agent/客户端/OneBox 版本，并执行真实回调、订阅导入和故障回滚。不得将此交付标记为生产验收通过。

## 额外低 PID LXC 验收（用户约束，非原规格 AT 编号）

20–30 的 `pids.max` 总额度场景尚未在目标 LXC 实测。插件已阻止同一探针上 KNS 远程 OneBox 任务重叠，OneBox 启动前按可见剩余额度执行门槛检查；本地逻辑不能证明目标容器内 sing-box、Agent、init 与其他进程/线程组合的峰值。验收时需记录 `pids.max`、`pids.current`、OneBox/Agent 版本和任务期间峰值，并分别执行发现、导入、安装、状态核查及并发请求，验证资源不足时安全拒绝且服务未被破坏。

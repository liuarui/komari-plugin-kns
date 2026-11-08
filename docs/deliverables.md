# 规格书交付项对照

| DEL | 规格要求 | 交付物/状态 |
| --- | --- | --- |
| 01 | 源码仓库与 Git Tag | OneBox 适配代码固定在 `liuarui/onebox` 提交 `a36b55c`（分支 `codex/kns-adapter`）。Komari 插件 v1.2.0 已发布；本轮 v1.2.2 修复目标后台在线状态映射和反代同源写入，完成目标扫描验收后发布 |
| 02 | Komari 插件安装/升级 ZIP | `dist/onebox-bridge.zip`，v1.2.2；包含 GNU AGPL v3.0-only 许可证文本，根 manifest、ZIP CRC 与 SHA-256 已核验。新增 `common:getNodesLatestStatus` 在线状态映射与 Fetch Metadata 反代写入兼容；尚未上传到目标面板。SHA-256 `ebc777d47b373b1aa3a0ae27c115ae2da5bf4c4df0ccf27410f9be3ee7fb4d64` |
| 03 | 打包脚本、依赖说明、SHA-256 | `scripts/package.py` 会校验机器可读 `requirements.lock` 并把锁文件哈希写入 CycloneDX SBOM；`dist/onebox-bridge.zip.sha256` |
| 04 | 安装/查询/卸载/重装适配器源码 | OneBox 仓库 `install.sh` KNS schema 1；包括旧节点 discover/import、install/reconfigure/reinstall/enable/disable/status/uninstall，以及低 PID/内存预检；实施结果与待验收项见 `OneBox_KNS_适配改造说明_2026-11-08.docx` |
| 05 | 数据模型、JSON Schema、迁移 | `docs/data-model.md`、`docs/state.schema.json`、`docs/migrations.md` |
| 06 | HTTP/回调 API 与错误码 | `docs/api.md` |
| 07 | 用户操作手册 | `docs/user-guide.md` |
| 08 | 管理员运维手册 | `docs/operations.md` |
| 09 | 测试代码与 AT 报告 | `tests/`、`docs/acceptance-report.md`、`docs/ux-acceptance-t40.md`；26 项本地 Node 测试通过，40 条交互验收逐项记录；真实浏览器/目标环境项目仍标明未执行 |
| 10 | Mihomo/URI/sing-box 样例及导入证据 | `docs/protocol-samples/` 样例已生成；冻结客户端导入证据待环境与版本提供 |
| 11 | 安全报告、依赖与许可证清单 | `docs/security-report.md`、`docs/license-report.md`、CycloneDX `docs/sbom.cdx.json` |
| 12 | 演示环境、交接录屏/培训 | 未提供可用目标 Komari/Agent 环境；未录制，不伪造 |
| 13 | 遗留限制、版本兼容矩阵 | `docs/compatibility-matrix.md` |
| 14 | 故障回滚与数据备份恢复演练 | 本地 store/key restore 测试通过；生产插件升级/目标机故障回滚尚未演练，步骤见 `docs/rollback-drill.md` |

此映射面向“可复核交付”，不是所有项目均已获得生产验收。无法完成的外部动作与环境测试在对应文档中明确标识。

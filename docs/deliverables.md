# 规格书交付项对照

| DEL | 规格要求 | 交付物/状态 |
| --- | --- | --- |
| 01 | 源码仓库与 Git Tag | OneBox 适配器已推送至 `liuarui/onebox` 的 `codex/kns-adapter`（当前 head `d9b98f0`）；Komari 插件 `v1.1.1` 发布至 `liuarui/komari-plugin-kns` 的 `main`，并带版本 tag |
| 02 | Komari 插件安装/升级 ZIP | `dist/onebox-bridge.zip`；包结构、CRC 和 SHA-256 已本地核验。因未取得目标 Komari 版本及现有插件 manifest，尚未验证覆盖升级；SHA-256 `64026b81999e38fd52f1c28640470a6d7426ede4ecd40eee65e041adb69074e1` |
| 03 | 打包脚本、依赖说明、SHA-256 | `scripts/package.py` 会校验机器可读 `requirements.lock` 并把锁文件哈希写入 CycloneDX SBOM；`dist/onebox-bridge.zip.sha256` |
| 04 | 安装/查询/卸载/重装适配器源码 | OneBox 仓库 `install.sh` KNS schema 1；包括旧节点 discover/import、install/reconfigure/reinstall/enable/disable/status/uninstall，以及低 PID/内存预检；实施结果与待验收项见 `OneBox_KNS_适配改造说明_2026-11-08.docx` |
| 05 | 数据模型、JSON Schema、迁移 | `docs/data-model.md`、`docs/state.schema.json`、`docs/migrations.md` |
| 06 | HTTP/回调 API 与错误码 | `docs/api.md` |
| 07 | 用户操作手册 | `docs/user-guide.md` |
| 08 | 管理员运维手册 | `docs/operations.md` |
| 09 | 测试代码与 AT 报告 | `tests/`、`docs/acceptance-report.md`；本地模拟可复现，真实目标 AT 未完成 |
| 10 | Mihomo/URI/sing-box 样例及导入证据 | `docs/protocol-samples/` 样例已生成；冻结客户端导入证据待环境与版本提供 |
| 11 | 安全报告、依赖与许可证清单 | `docs/security-report.md`、`docs/license-report.md`、CycloneDX `docs/sbom.cdx.json` |
| 12 | 演示环境、交接录屏/培训 | 未提供可用目标 Komari/Agent 环境；未录制，不伪造 |
| 13 | 遗留限制、版本兼容矩阵 | `docs/compatibility-matrix.md` |
| 14 | 故障回滚与数据备份恢复演练 | 本地 store/key restore 测试通过；生产插件升级/目标机故障回滚尚未演练，步骤见 `docs/rollback-drill.md` |

此映射面向“可复核交付”，不是所有项目均已获得生产验收。无法完成的外部动作与环境测试在对应文档中明确标识。

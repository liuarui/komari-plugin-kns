# 依赖与许可证清单

## Komari KNS 插件

- Runtime 无第三方 Node.js package 依赖；仅使用 Komari MoeJS APIs、Node 兼容内置模块 `fs`、`path`、`crypto`、`net`、`tls` 与标准 `fetch`。
- `scripts/package.py` 与生成器只使用 Python 标准库 `hashlib`、`json`、`pathlib`、`zipfile`。
- 此工作区没有 KNS 项目许可证文件或已确认的 SPDX 标识；发布到公开源码仓库前需由项目权利人选择并加入许可证。当前 SBOM 不把宿主 Komari、OneBox 或客户端当作内置依赖。

## 上游与外部服务

| 项目/服务 | 使用方式 | 许可证/核验 |
| --- | --- | --- |
| OneBox | 目标探针安装器源码仓库；KNS 调用其固定版本 | 仓库根 `LICENSE` 声明 MIT。KNS 不复制其完整源文件进插件 ZIP |
| Komari | 插件运行宿主与 Agent RPC | 作为外部宿主；以所部署 Komari 仓库/发行物的许可证为准 |
| SubConverter-Extended | 用户已有订阅转换服务；通过 HTTP URL 外部调用 | 访问页面声明 GPL-3.0；未核实运行二进制的 commit/build，也未随包分发 |
| Mihomo、sing-box | 订阅输出格式和远端 OneBox Runtime | 客户端/Runtime 外部组件；未随 KNS ZIP 分发 |

SBOM 文件见 `sbom.cdx.json`。当前 components 为空是因为插件包无第三方库；运行宿主和远端软件是部署依赖，列在本清单但未作为 ZIP components。打包发布前应根据最终依赖差异更新 SPDX/许可证结论。

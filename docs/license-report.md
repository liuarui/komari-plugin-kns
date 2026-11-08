# 依赖与许可证清单

## Komari KNS 插件

- Runtime 无第三方 Node.js package 依赖；仅使用 Komari 插件 APIs、Node 兼容内置模块 `fs`、`path`、`crypto`、`net`、`tls`、`url` 与标准 `fetch`。Komari 1.6.1 使用 MoeJS；兼容下限所审查的 1.4.3 使用 Goja。
- `scripts/package.py` 与生成器只使用 Python 标准库 `hashlib`、`json`、`pathlib`、`zipfile`。
- KNS 插件按 GNU Affero General Public License version 3 发布，SPDX 标识为 `AGPL-3.0-only`。根目录 `LICENSE` 的完整许可证文本随源码和插件 ZIP 一起分发；管理页与订阅响应也标识该许可证及源码地址。
- 当前没有第三方 Node.js runtime package。SBOM 将插件本身标为 `AGPL-3.0-only`，不把宿主 Komari、OneBox、SubConverter 或客户端误列为随包内置依赖。

## 上游与外部服务

| 项目/服务 | 使用方式 | 许可证/核验 |
| --- | --- | --- |
| OneBox | 目标探针安装器源码仓库；KNS 调用其固定版本 | 仓库根 `LICENSE` 声明 MIT。KNS 不复制其完整源文件进插件 ZIP |
| Komari | 插件运行宿主与 Agent RPC | 作为外部宿主；以所部署 Komari 仓库/发行物的许可证为准 |
| SubConverter-Extended | 用户已有订阅转换服务；通过 HTTP URL 外部调用 | 访问页面声明 GPL-3.0；未核实运行二进制的 commit/build，也未随包分发 |
| Mihomo、sing-box | 订阅输出格式和远端 OneBox Runtime | 客户端/Runtime 外部组件；未随 KNS ZIP 分发 |

SBOM 文件见 `sbom.cdx.json`。插件源码与运行包使用同一 SPDX 标识；运行宿主和远端软件是部署依赖，列在本清单但未作为 ZIP components。增加或打包第三方组件时应重新核验组件许可证并更新 SBOM。

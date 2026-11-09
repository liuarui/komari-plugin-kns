# 备份恢复与回滚演练记录

## 已执行的本地模拟

自动化用例 `tests/store.test.js` 已覆盖：原子写 state、创建每日备份、恢复匹配日期备份；明文 state 的恢复不依赖 master key。执行命令：

```sh
node --test tests/store.test.js
```

结果会在本次完整本地验证后更新。该演练使用临时目录，不访问生产 Komari storage，也不验证 systemd/OpenRC 或目标节点配置回滚。

## 生产回滚步骤（目标环境执行前检查）

1. 记录当前 Komari 插件版本、ZIP SHA、`__storageDir__/kns/state.json` 修订、OneBox installer SHA、目标 OneBox `status` 和节点监听。
2. 在管理页导出加密备份，设置至少 12 个字符的独立口令；将口令存入密码管理器，与文件分开保管。若备份中仍有旧版密文字段，另行复制匹配日期的 `kns/master.key` 或安全记录 `KNS_MASTER_KEY`。
3. 安装升级 ZIP；确认 Komari 页面状态路由、插件日志、机器清单和订阅格式后，再对一台已授权探针跑只读 status。
4. 若插件不能正常加载，先禁用插件并恢复原 ZIP。不要删除新 storage 或启动不认识 schema 的旧插件。
5. 若从加密导出恢复，在管理页选择文件并输入原口令；导入会保留 `pre-import-*`。若从每日 state/key 恢复，停止插件写入后按日恢复匹配文件并保留 `pre-restore-*`。重新启用后核对 profile token、实例凭据可用性和备份清单。
6. 若远程 OneBox 配置需要回滚，优先使用 adapter 事务已保留的配置备份，并核对非 KNS inbound、服务状态和防火墙规则。卸载 KNS 实例不卸载共享 OneBox Runtime。
7. 保存前后 state revision、job ID、日志时间、目标机状态与订阅 URL 可用性作为验收证据。

## 未完成项

尚未在用户生产 Komari 实例或真实 OneBox 探针进行插件版本回退、state 恢复、共享 Runtime 保护和失败注入演练。上述步骤是执行方案，不是生产演练已通过的声明。

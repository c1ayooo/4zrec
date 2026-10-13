---
name: vuln-adjudication-policy
description: 漏洞判定政策——三分类与误报边界的唯一口径。Use when Codex is about to record_vulnerability, generate_report, classify a finding as confirmed / suspected / false_positive, decide what counts as evidence, or close out a checked-but-clean area. 触发词:判定政策、定性、判读、误报、false positive、上报门槛、五项报告门槛、证据不足、降级、收口、漏洞确认、留痕。任何把发现写成 confirmed 的动作之前必须先过本政策。
metadata:
  roles: [默认, 漏洞扫描, 渗透测试]
  stages: [vuln, src]
---

# 漏洞判定政策(Adjudication Policy)

> **AI LOAD INSTRUCTION**: 本文档是判定口径的唯一事实源:三分类判据、五项报告门槛、10 条误报边界闭集。
> record_vulnerability / generate_report 的 confirmed 入库纪律、laya 判读四问的 vuln_screen 判据均引用本文。
> 三条原则:先分类后严重度;证据不足只能降级不能升类;环境噪音不是漏洞证据。

## 一、三分类(闭集,不得自造第四类)

| 分类 | 判据 | 典型信号 |
|---|---|---|
| confirmed | 可复现的输入-输出对:构造输入 → 目标异常响应,且输入与输出同时在证据里 | payload 回显/命令输出、数据实际取出、会话或权限实际获得、同一输入可重复触发同一异常 |
| suspected | 有漏洞信号但不完整,等待验证 | 反射未闭合、报错堆栈/路径泄露、版本命中已知 CVE 但无 PoC 验证、时序/布尔差异、WAF 拦截提示存在过滤 |
| false_positive | 正常响应、环境噪音、或命中 §三 误报边界任意一条 | 见 §三 |

铁律:
1. **多条 suspected 不得叠加成 confirmed**——升类必须出现新的独立可复现证据。
2. **严重度与分类正交**——High 严重度也可以只是 suspected;先有分类,再谈严重度。
3. 无法判读(证据被截断、工具自身失败)→ 不落分类,修复采集后重判;不得默认 false_positive。

## 二、五项报告门槛(confirmed 上库前逐项自检,缺一降级 suspected 或不入库)

1. **位置**:精确到行号/端点/参数/文件路径,第三方可复走;
2. **触发条件**:什么输入、什么前置状态下危险行为发生;
3. **输入来源**:谁可控(匿名用户/低权用户/已控凭据)——不可控输入不构成漏洞主证;
4. **危险操作**:机密性/权限/可用性哪一面受损,损害语义明确;
5. **越过的信任边界**:从哪个域跨到哪个域(匿名→认证、低权→高权、DMZ→内网核心)——没有跨界的是配置卫生,不是漏洞。

缺任何一项:降 suspected 或不入库;不得为凑报告补写臆测字段。

## 三、10 条误报边界闭集(命中任意一条,该条单独不构成 confirmed/suspected 依据)

1. `curl|sh` / `wget -qO- … | sh` 出现在文档、README、部署脚本——安装惯例,不是命令注入;
2. 依赖版本未锁定(pin 缺失)——供应链卫生,单独不构成漏洞;
3. 请求携带 Authorization 头 / Bearer token——授权测试的预期形态,不是凭据泄露;
4. 回显的是测试方自身凭据(平台令牌、工具 key、模板占位串)——不是目标凭据;
5. 版本号/banner 披露本身——无已验证 exploit 路径时至多 suspected,通常是 false_positive;
6. WAF 拦截页、403、连接重置、超时——环境噪音(failure=environmental),不是漏洞证据;
7. 登录页/认证表单存在——不等于弱口令;爆破未成功即无洞;
8. 自签/过期证书、安全响应头缺失——低危配置项,不得据此判 confirmed;
9. 工具汇总统计行("found 42 hosts"、"scan complete")——收集面统计,不是漏洞;
10. 多信号叠加禁令——即 §一铁律 1,重申以防绕行。

## 四、与平台机制的衔接

- **record_vulnerability / generate_report**:confirmed 入库前过 §二 五项门槛;引文必须是工具回执的子串,对不上不得入 confirmed(引用失真=报告失真)。
- **laya 判读(internal/tooljudge vuln_screen)**:三分类与 §三 闭集已内嵌于判读问题的 criteria;改动本文必须同步该处,守门测试 `TestJudgeQuestionsEmbedAdjudicationPolicy` 把关。
- **「查过但没洞」**:必须在信息黑板留痕,不得静默丢弃——没有留痕的"测过了"在收尾对账时等于没测。
- **收口对账**:报告收尾时对照缺口清单,「判定不可能/超出范围」要显式写进收尾,不得留悬空项。

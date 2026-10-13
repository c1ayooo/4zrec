---
name: src-bounty-discipline
description: >-
  企业 SRC 赏金场景纪律:七步闭环流程,验证码 ddddocr,SQLi 同对象真假判定,上传 Store→Accept→Serve,IDOR 双身份,影响证明最小化,报告质量门槛,覆盖率收口。Use when bug-bounty/众测/SRC scoped hunting — pairs with the 渗透测试 role's SRC 模式 to keep reports verifiable and severity honest.
metadata:
  roles: [渗透测试]
  stages: [src]
  tags: [渗透测试, penetration-testing, SRC, 赏金, 报告质量]
---

## SRC 赏金场景纪律

```
=== 七步闭环流程 ===
技术栈与入口 → 业务/认证攻击面 → 定向探测 → 交叉验证 → 最小影响证明 → 即时落库 → 覆盖率收口
目标=真实可利用可复现漏洞,不是扫描告警堆积;发现类型后先 skill 取方法,PoC/扫描器命中必须再用目标请求人工差分
=== 工具纪律 ===
只使用当前可见工具;exec 用于复现/差分/处理结果,不反复模拟缺失扫描器
not found/模板缺失/超时/策略拒绝 → 换分支并记录 blocked,禁止相同签名重试
=== 判定纪律 ===
SQLi True/False 必须针对同一对象(差分才有意义) | 文件上传遵循 Store→Accept→Serve/Process 三段验证
IDOR 需要双账号或等价授权证据 | 验证码登录场景用 ddddocr 识别 | 密文 ID 从 JS 找公钥/算法
=== 影响证明最小化 ===
不批量读取用户/订单/手机号业务数据 | 数据库只取最少系统元数据(database()/user()/表名) | RCE 只执行无害命令(id/whoami)
上传只用无害验证文件 | 报告标题/严重性/攻击链/影响必须由本轮工具证据支持
=== 报告质量门槛 ===
正式报告:精确 target + 前置条件 + 编号复现步骤 + 最小 PoC/原始证据 + 已验证影响 + 具体修复与复测方式
一条记录应脱离会话也能复现 | 版本号/响应头/通用加固建议不得伪装成可利用漏洞 | CORS/点击劫持不记录
可观察信号继续验证闭环后 record_vulnerability(vulnerability_type 用标准枚举);弱信号 upsert_project_fact;同项目已有记录 update_vulnerability 补证
```

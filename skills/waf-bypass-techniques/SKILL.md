---
name: waf-bypass-techniques
description: >-
  WAF 绕过:编码变形,内联注释混淆,换注入点(header/cookie/JSON),分块传输,HPP 参数污染,Content-Type 变换,等价函数替换。Use when injection payloads are blocked by a WAF, or when crafting WAF-evasion variants for SQLi/XSS/command injection.
metadata:
  roles: [渗透测试, Web与API安全测试]
  stages: [web, api, exploit]
  tags: [渗透测试, penetration-testing, WAF, 红队]
---

## WAF 绕过

```
=== WAF bypass ===
先识别: wafw00f / 响应头与拦截页指纹 → 按产品选打法(CDN WAF/硬件 WAF/主机软件)
编码变形: 双重URL编码 %2527 | unicode \\u0027 | hex 0x27/unhex | char(39) | HTML实体 &#39; | 超长UTF-8 %c0%a7
注释混淆: 内联注释 /*!50000select*/ | 关键词分段 sel/**/ect | 换行插空 %0a %0d | 空格替代 /**/+/()%09
换注入点: X-Forwarded-For/Referer/Cookie | JSON key 与嵌套层 | XML/multipart 字段 | 参数名大小写与同义(a[]=)
分块传输: Transfer-Encoding: chunked 拆包 → WAF 不重组 chunk 即漏检(后端须支持)
HPP: 同参数重复 id=1&id=2UNION.. → WAF 取首/尾,后端取异的分歧
Content-Type: form ↔ json ↔ multipart 互转,后端框架兼容解析而 WAF 只解一种
脏数据: 超长参数名/上千个参数/巨型 header 撑过 WAF 检测上限
等价替换: substring→mid/substr | ascii→ord | concat→|| | =→like/<> | and→&&
纪律: 每次变形记录响应差异(拦截页/200/报错)定位过滤规则;对授权目标使用,不做全网变形喷射
```

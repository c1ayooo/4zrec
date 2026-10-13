---
name: path-403-bypass
description: >-
  403/路径鉴权绕过:%2e 编码,分号与 /..;/ 路径参数,大小写/双斜杠/尾缀变形,X-Original-URL 头,方法变换,Host 直指源站。Use when a path returns 403/401 and you need path-traversal style auth bypass variants before declaring it dead.
metadata:
  roles: [Web与API安全测试, 渗透测试]
  stages: [web]
  tags: [渗透测试, penetration-testing, 红队]
---

## 403 / 路径鉴权绕过

```
=== 403 bypass ===
路径变形: %2e(%2e%2e%2f) | 分号 /;;/ | /..;/ (Spring/Tomcat off-by-slash) | //双斜杠 | /./ | 尾斜杠 /admin/ ↔ /admin
大小写/后缀: /ADMIN /Admin | /admin.json /admin.css /admin%20 /admin.. /admin? | /api/v1/../admin
路径参数: /admin;param=value (Spring 矩阵变量) | /admin;x=1/admin
头注入: X-Original-URL / X-Rewrite-URL: https://target/admin | X-Forwarded-For/X-Real-IP: 127.0.0.1 | X-Custom-IP-Authorization | Referer/Origin 改站内
方法变换: GET→POST/PUT/HEAD/PATCH | 目录 403 试具体文件 /admin/index.html /admin/main.js
绕反代/CDN: 证书透明度/历史 DNS/子域猜解找源站 IP → Host 头直指源站跳过 WAF 层
判死纪律: 变形至少过一整轮(编码/分号/头/方法各试) + SPA 兜底校验(200 但内容同首页 → Accept: application/json 重打对照)才判 dead;判死记 pathfamily/<host>/<族名>=dead Fact 不再重探
```

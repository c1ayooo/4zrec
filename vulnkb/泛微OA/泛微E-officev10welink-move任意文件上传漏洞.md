# 泛微E-officev10welink-move任意文件上传漏洞

泛微OA ｜ 文件上传 ｜ —
- **请求**：`POST /eoffice10/server/public/api/welink/welink-move HTTP/1.1`
- **响应特征**：200 ^(?=.*?code)(?=.*?0x000013).*?$
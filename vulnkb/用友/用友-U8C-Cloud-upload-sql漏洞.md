# 用友-U8C-Cloud-upload-sql漏洞

用友 ｜ 其他 ｜ —
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /u8cloud/api/hr/attachment/upload?mssql_error HTTP/1.1`
- **响应特征**：200 ^(?=.*?12321)(?=.*?errorcode).*?$
